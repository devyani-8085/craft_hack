"""
Expected artifact type: cloud_service (category 'Cloud KMS')
Matches scanner/regex_analyzer.py::_KMS_HSM_PATTERNS -> KeyClient/SecretClient/vault.azure.net
"""
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient

VAULT_URL = "https://cryptoscan-fixture.vault.azure.net"

credential = DefaultAzureCredential()
key_client = KeyClient(vault_url=VAULT_URL, credential=credential)


def get_signing_key(key_name: str):
    """Retrieves a hardware-protected signing key reference from Azure Key Vault."""
    return key_client.get_key(key_name)
