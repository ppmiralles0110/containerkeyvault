# Container App Key Vault demo

This repository contains a minimal Python Flask app designed to run in a container and demonstrate retrieving a secret from Azure Key Vault using Managed Identity.

Features
- Uses DefaultAzureCredential from the Azure Identity library so the app can authenticate with Managed Identity when running in Azure Container Apps
- Attempts to show token claims (decoded) to give evidence that a Managed Identity (system- or user-assigned) was used
- Does NOT print secret values (security best practice) — only confirms success/failure and shows a masked secret length

Required environment variables
- KEY_VAULT_URL: The vault URL, e.g. https://myvault.vault.azure.net/
- SECRET_NAME: Name of the secret (default: `demo-secret`)
- (optional) AZURE_CLIENT_ID: If you want to use a user-assigned managed identity, set this to that identity's client id

Build and push to Azure Container Registry (example)

1. Build locally and tag for ACR

   docker build -t myapp:latest .
   docker tag myapp:latest <registry-name>.azurecr.io/myapp:latest

2. Login to ACR and push

   az acr login --name <registry-name>
   docker push <registry-name>.azurecr.io/myapp:latest

Azure steps (high-level)

1. Ensure your Container App has a managed identity (system-assigned or user-assigned). Example:

   # assign system-assigned
   az containerapp identity assign --name <app-name> --resource-group <rg> --system-assigned

   # assign user-assigned (example requires the resource id of the user-assigned identity)
   az containerapp identity assign --name <app-name> --resource-group <rg> --user-assigned <identity-resource-id>

2. Grant the identity rights to access secrets in Key Vault. Using Azure RBAC (recommended):

   # get the Key Vault resource id
   vaultId=$(az keyvault show -n <vault-name> -g <rg> --query id -o tsv)

   # give the identity the "Key Vault Secrets User" role on the vault
   az role assignment create --assignee <principal-id-or-client-id> --role "Key Vault Secrets User" --scope $vaultId

   Alternatively, using Key Vault access policies (legacy) you can use `az keyvault set-policy` to grant GET permissions on secrets.

3. Configure the Container App to include environment variables `KEY_VAULT_URL` and `SECRET_NAME` and (if using user-assigned identity) `AZURE_CLIENT_ID`.

4. Deploy or update the container app to point to the ACR image

   az containerapp update --name <app-name> -g <rg> --image <registry-name>.azurecr.io/myapp:latest

References
- Quickstart: Use a managed identity to access Key Vault from Azure App Service or Function: https://learn.microsoft.com/azure/app-service/overview-managed-identity
- Key Vault secrets client library for Python: https://learn.microsoft.com/azure/key-vault/secrets/quick-create-python
- DefaultAzureCredential docs: https://learn.microsoft.com/azure/developer/python/azure-sdk-authenticate

Security notes
- Do not print or log secret values in production
- Use least privilege when assigning roles
- Prefer managed identity + Key Vault over client secrets
