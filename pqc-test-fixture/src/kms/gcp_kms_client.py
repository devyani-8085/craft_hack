"""
Expected artifact type: cloud_service (category 'Cloud KMS')
Matches scanner/regex_analyzer.py::_KMS_HSM_PATTERNS -> KeyManagementServiceClient
"""
from google.cloud import kms

kms_client = kms.KeyManagementServiceClient()


def encrypt_with_gcp_kms(key_path: str, plaintext: bytes) -> bytes:
    """Envelope-encrypts data using a GCP Cloud KMS-managed key."""
    response = kms_client.encrypt(request={"name": key_path, "plaintext": plaintext})
    return response.ciphertext
