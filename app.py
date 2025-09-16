"""
Flask app that demonstrates access to Azure Key Vault using Managed Identity.

Behavior:
- Reads KEY_VAULT_URL and SECRET_NAME from environment variables
- Uses DefaultAzureCredential to authenticate (works with managed identity in Azure)
- Requests a token for Key Vault and decodes the JWT to extract identity claims
- Attempts to read the secret; on success displays confirmation (without revealing the secret value)
- Shows which identity claims were present in the token (e.g., oid/appid) so you can confirm Managed Identity use

References:
- Azure Key Vault secrets with managed identity (Python):
  https://learn.microsoft.com/azure/key-vault/secrets/quick-create-python
- Azure Identity DefaultAzureCredential:
  https://learn.microsoft.com/azure/active-directory/develop/msi-overview

Security notes:
- The secret value is NOT displayed in this demo. Only a success/failure message and masked info are shown.
"""

import os
import logging
import time
import base64
import json

from flask import Flask, render_template_string
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import AzureError
import jwt  # PyJWT - used only to decode token payload without signature verification

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("container-keyvault-app")

app = Flask(__name__)

# Configuration - prefer environment variables
KEY_VAULT_URL = os.environ.get("https://container-test-01-vault.vault.azure.net/")  # e.g., https://myvault.vault.azure.net/
SECRET_NAME = os.environ.get("SECRET_NAME", "aca-key-01")
PORT = int(os.environ.get("PORT", "8080"))

# HTML template - simple, self-contained
TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Container App KeyVault Demo</title>
    <style>
      body { font-family: Arial, Helvetica, sans-serif; margin: 2rem; }
      .ok { color: green; }
      .err { color: red; }
      .card { border: 1px solid #ddd; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
      pre { background: #f6f8fa; padding: 0.75rem; border-radius: 4px; }
    </style>
  </head>
  <body>
    <h1>Container App Key Vault demo</h1>
    <div class="card">
      <strong>Key Vault:</strong> {{ keyvault_url or 'Not configured' }}<br />
      <strong>Secret name:</strong> {{ secret_name }}
    </div>

    <div class="card">
      <h2>Secret retrieval status</h2>
      {% if success %}
        <p class="ok">You successfully pulled the secret from Key Vault.</p>
        <p>Secret value is hidden for security. (Length: {{ secret_len }} characters)</p>
      {% else %}
        <p class="err">Failed to pull secret from Key Vault.</p>
        <p>Error: <code>{{ error_message }}</code></p>
      {% endif %}
    </div>

    <div class="card">
      <h2>Managed Identity / Token claims</h2>
      {% if token_claims %}
        <p>Decoded token claims used to authenticate to Key Vault (signature not verified).</p>
        <pre>{{ token_claims }}</pre>
      {% else %}
        <p>No token available or could not decode token.</p>
      {% endif %}
      <p>Environment hints: <code>AZURE_CLIENT_ID={{ azure_client_id }}</code></p>
    </div>

    <div class="card">
      <h2>Notes</h2>
      <ul>
        <li>This app uses DefaultAzureCredential which will attempt Managed Identity when running in Azure.
        To target a user-assigned identity, set <code>AZURE_CLIENT_ID</code> environment variable to the client-id of the identity.</li>
        <li>Do not expose secret values in production UIs. This demo only shows success/failure and masked info.</li>
      </ul>
    </div>
  </body>
</html>
"""


@app.route("/")
def index():
    if not KEY_VAULT_URL:
        return render_template_string(TEMPLATE, keyvault_url=None, secret_name=SECRET_NAME, success=False,
                                      error_message="KEY_VAULT_URL not configured in environment", token_claims=None,
                                      secret_len=0, azure_client_id=os.environ.get("AZURE_CLIENT_ID"))

    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

    # We'll attempt to acquire a token so we can inspect the token claims and prove which identity was used
    token_claims = None
    try:
        # Acquire a token for Key Vault resource
        scope = "https://vault.azure.net/.default"
        access_token = credential.get_token(scope)
        token_string = access_token.token

        # Decode JWT payload without verifying signature to inspect claims like 'oid' or 'appid'
        try:
            decoded = jwt.decode(token_string, options={"verify_signature": False})
            # Keep only a subset of claims for tidy output
            claims_to_show = {k: decoded.get(k) for k in ("aud", "iss", "exp", "nbf", "iat", "oid", "appid", "upn") if decoded.get(k) is not None}
            token_claims = json.dumps(claims_to_show, indent=2)
        except Exception as ex:
            logger.warning("Failed to decode token: %s", ex)
            token_claims = f"Failed to decode token: {ex}"

    except Exception as ex:
        logger.exception("Failed to acquire token using DefaultAzureCredential: %s", ex)
        return render_template_string(TEMPLATE, keyvault_url=KEY_VAULT_URL, secret_name=SECRET_NAME, success=False,
                                      error_message=f"Failed to get token: {ex}", token_claims=None,
                                      secret_len=0, azure_client_id=os.environ.get("AZURE_CLIENT_ID"))

    # Attempt to fetch the secret with a simple retry/backoff
    max_retries = 3
    backoff_seconds = 1
    last_error = None
    secret_len = 0

    for attempt in range(1, max_retries + 1):
        try:
            logger.info("Attempt %d to get secret '%s' from %s", attempt, SECRET_NAME, KEY_VAULT_URL)
            secret = secret_client.get_secret(SECRET_NAME)
            secret_value = secret.value
            secret_len = len(secret_value) if secret_value is not None else 0
            logger.info("Successfully retrieved secret (length=%d)", secret_len)
            return render_template_string(TEMPLATE, keyvault_url=KEY_VAULT_URL, secret_name=SECRET_NAME, success=True,
                                          error_message=None, token_claims=token_claims, secret_len=secret_len,
                                          azure_client_id=os.environ.get("AZURE_CLIENT_ID"))

        except AzureError as ae:
            last_error = str(ae)
            logger.warning("AzureError on attempt %d: %s", attempt, ae)
        except Exception as ex:
            last_error = str(ex)
            logger.exception("Unexpected error on attempt %d: %s", attempt, ex)

        # Backoff
        time.sleep(backoff_seconds)
        backoff_seconds *= 2

    # If we reach here, all retries failed
    error_message = last_error or "Unknown error"
    return render_template_string(TEMPLATE, keyvault_url=KEY_VAULT_URL, secret_name=SECRET_NAME, success=False,
                                  error_message=error_message, token_claims=token_claims, secret_len=secret_len,
                                  azure_client_id=os.environ.get("AZURE_CLIENT_ID"))


if __name__ == "__main__":
    # For local testing only; in container use a production WSGI server
    app.run(host="0.0.0.0", port=PORT)
