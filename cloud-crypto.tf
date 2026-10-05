# Expected artifact type: cloud_service (AWS KMS / ACM / CloudHSM, Azure Key Vault, GCP KMS) + key algorithms
resource "aws_kms_key" "payments" {
  description              = "payments signing key"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "legacy_sym" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = false
}
resource "aws_kms_key" "pq_ready" {
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_cloudhsm_v2_cluster" "hsm" {
  hsm_type   = "hsm1.medium"
  subnet_ids = []
}
resource "aws_acm_certificate" "api" {
  domain_name = "api.cryptoscan-fixture.example.com"
  key_algorithm = "RSA_2048"
}
resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"
}
resource "azurerm_key_vault_key" "k" {
  key_type = "RSA-HSM"
  key_size = 2048
}
resource "google_kms_crypto_key" "k" {
  version_template { algorithm = "RSA_SIGN_PKCS1_2048_SHA256" }
}
resource "google_kms_crypto_key" "pq" {
  version_template { algorithm = "PQ_SIGN_ML_DSA_65" }
}
