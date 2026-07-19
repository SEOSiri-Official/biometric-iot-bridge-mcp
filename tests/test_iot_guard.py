# tests/test_iot_guard.py
import json
import os
import sys
import time

# Force the project root directory into the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main_server import secure_biometric_iot_gatekeeper

def test_unified_biometric_gatekeeper_flow():
    SHARED_DEVICE_KEY = b"seosiri_biometric_iot_secret_2026"
    student_id = "student_badhan"
    action = "iot/unlock"
    timestamp = int(time.time())
    
    # 1. Generate correct token
    import hmac
    import hashlib
    payload = f"{student_id}:{action}:{timestamp}".encode('utf-8')
    correct_token = hmac.new(SHARED_DEVICE_KEY, payload, hashlib.sha256).hexdigest()
    
    # 2. Test successful verification and authorization
    res_raw_1 = secure_biometric_iot_gatekeeper(student_id, correct_token, action, timestamp)
    res_1 = json.loads(res_raw_1)
    assert res_1["status"] == "AUTHORIZED"
    assert res_1["gcode_actuation_command"] == "G1 X180.0 F500.0"
    
    # 3. Test Anti-Replay Protection (trying to use the exact same token again)
    res_raw_2 = secure_biometric_iot_gatekeeper(student_id, correct_token, action, timestamp)
    res_2 = json.loads(res_raw_2)
    assert res_2["status"] == "REJECTED"
    assert res_2["reason"] == "SIGNATURE_REUSE_DETECTED"
    
    # 4. Test Temporal Protection (trying to pass an old timestamp)
    old_timestamp = timestamp - 400 # 6.6 minutes in past
    old_payload = f"{student_id}:{action}:{old_timestamp}".encode('utf-8')
    old_token = hmac.new(SHARED_DEVICE_KEY, old_payload, hashlib.sha256).hexdigest()
    
    res_raw_3 = secure_biometric_iot_gatekeeper(student_id, old_token, action, old_timestamp)
    res_3 = json.loads(res_raw_3)
    assert res_3["status"] == "REJECTED"
    assert res_3["reason"] == "TEMPORAL_WINDOW_VIOLATION"
    
    # 5. Test Forgery Protection (tampered signature)
    # We must use an unused, altered token so it is not caught by the Anti-Replay registry first
    forged_token = correct_token[:-1] + "0" # Modify the last character of the signature hash
    res_raw_4 = secure_biometric_iot_gatekeeper(student_id, forged_token, action, timestamp)
    res_4 = json.loads(res_raw_4)
    assert res_4["status"] == "REJECTED"
    assert res_4["reason"] == "CRYPTOGRAPHIC_SIGNATURE_MISMATCH"