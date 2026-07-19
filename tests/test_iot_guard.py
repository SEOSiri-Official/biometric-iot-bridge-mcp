# tests/test_iot_guard.py
import json
import os
import sys

# Force the project root directory into the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main_server import verify_biometric_token, authorize_agent_actuation

def test_biometric_token_verification_and_spasm_blocking():
    # 1. Test invalid signature blocking
    res_raw = verify_biometric_token("student_badhan", "invalid_forged_token", "iot/unlock")
    res = json.loads(res_raw)
    assert res["status"] == "REJECTED"
    
    # 2. Assert agent actuation is blocked when no session is active
    act_raw_1 = authorize_agent_actuation("student_badhan", "iot/unlock")
    act_res_1 = json.loads(act_raw_1)
    assert act_res_1["status"] == "BLOCKED"
    assert act_res_1["reason"] == "NO_ACTIVE_BIOMETRIC_SESSION"

    # 3. Generate correct cryptographic token for testing
    import hmac
    import hashlib
    SHARED_DEVICE_KEY = b"seosiri_biometric_iot_secret_2026"
    payload = b"student_badhan:iot/unlock"
    correct_token = hmac.new(SHARED_DEVICE_KEY, payload, hashlib.sha256).hexdigest()
    
    # 4. Test successful verification
    res_raw_2 = verify_biometric_token("student_badhan", correct_token, "iot/unlock")
    res_2 = json.loads(res_raw_2)
    assert res_2["status"] == "AUTHENTICATED"
    
    # 5. Assert agent actuation is approved when session is active
    act_raw_2 = authorize_agent_actuation("student_badhan", "iot/unlock")
    act_res_2 = json.loads(act_raw_2)
    assert act_res_2["status"] == "APPROVED"
    assert act_res_2["gcode_actuation_command"] == "G1 X180.0 F500.0"
