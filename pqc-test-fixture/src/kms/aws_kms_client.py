"""
Expected artifact type: cloud_service (category 'Cloud KMS')
Matches scanner/regex_analyzer.py::_KMS_HSM_PATTERNS -> boto3.client('kms')
"""
import boto3

kms_client = boto3.client("kms")


def sign_with_kms(key_id: str, message: bytes) -> bytes:
    """Hardware-backed signing via AWS KMS — key material never leaves the HSM."""
    response = kms_client.sign(
        KeyId=key_id,
        Message=message,
        SigningAlgorithm="RSASSA_PSS_SHA_256",
    )
    return response["Signature"]
