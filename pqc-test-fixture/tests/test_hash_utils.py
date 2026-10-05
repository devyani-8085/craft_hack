"""
Unit test helper for the internal hashing utility.
Expected classification: Business Criticality = LOW (score ~1.0)
  Sens=1.0 (no sensitive keyword) | Exp=1.0 (internal /tests/ path)
  Sys=1.0 (non-production test dir) | Reg=1.0 (no compliance keyword)
Expected Exposure = Internal (isInternalFileType: '/tests/' path match)
"""
import hashlib


def sample_checksum(payload: bytes) -> str:
    """Non-sensitive test fixture: hashes a dummy blob for a unit test assertion."""
    return hashlib.sha256(payload).hexdigest()


def test_sample_checksum_matches_known_value():
    result = sample_checksum(b"fixture-blob")
    assert isinstance(result, str)
    assert len(result) == 64
