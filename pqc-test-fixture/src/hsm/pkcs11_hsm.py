"""
Expected artifact type: hardware_module (category 'Hardware Module')
Matches scanner/regex_analyzer.py::_KMS_HSM_PATTERNS -> PyKCS11 / C_Initialize / C_OpenSession
"""
import PyKCS11

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load("/usr/lib/softhsm/libsofthsm2.so")
pkcs11.C_Initialize()


def open_hsm_session(slot_id: int):
    """Opens a session with the physical/virtual HSM slot for key custody operations."""
    session = pkcs11.C_OpenSession(slot_id, PyKCS11.CKF_SERIAL_SESSION)
    return session
