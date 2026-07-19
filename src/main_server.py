# src/main_server.py
import os
import sys
import json
import hmac
import hashlib
import time

# Force the project root directory into the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("SEOSiri-Biometric-IoT-Guard")

# Shared cryptographic key used by the Flutter app's token generator
SHARED_DEVICE_KEY = b"seosiri_biometric_iot_secret_2026"

# Anti-Replay Registry: Keeps track of used signatures within the 5-minute window
# to completely prevent replay attacks locally without database dependencies.
USED_SIGNATURES_REGISTRY = {}

@mcp.tool()
def secure_biometric_iot_gatekeeper(student_id: str, biometric_token: str, proposed_action: str, timestamp_epoch: int) -> str:
    """
    Unified Biometric IoT Gatekeeper: Authenticates mobile biometric tokens,
    enforces strict temporal anti-replay bounds, and authorizes safe robotic actuation.
    """
    clean_id = student_id.strip().lower()
    clean_action = proposed_action.strip().lower()
    token = biometric_token.strip().lower()
    
    # 1. Temporal Check: Prevent replay attacks by enforcing a strict 5-minute (300 seconds) window
    current_time = int(time.time())
    if abs(current_time - timestamp_epoch) > 300:
        return json.dumps({
            "status": "REJECTED",
            "reason": "TEMPORAL_WINDOW_VIOLATION",
            "message": "Transaction timestamp is outside the secure 5-minute window. Potential replay attack."
        })
        
    # 2. Anti-Replay Check: Ensure the exact same signature has not been processed already
    if token in USED_SIGNATURES_REGISTRY:
        return json.dumps({
            "status": "REJECTED",
            "reason": "SIGNATURE_REUSE_DETECTED",
            "message": "This specific cryptographic signature has already been processed and revoked."
        })
        
    # 3. Cryptographic Signature Check: Recalculate HMAC-SHA256
    # Expected payload format: "student_id:proposed_action:timestamp_epoch"
    payload = f"{clean_id}:{clean_action}:{timestamp_epoch}".encode('utf-8')
    expected_token = hmac.new(SHARED_DEVICE_KEY, payload, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_token, token):
        return json.dumps({
            "status": "REJECTED",
            "reason": "CRYPTOGRAPHIC_SIGNATURE_MISMATCH",
            "message": "Token verification failed. Potential tampering or un-shared secret."
        })
        
    # 4. Register used signature in the anti-replay log
    USED_SIGNATURES_REGISTRY[token] = current_time + 300 # Keep in registry until the window expires
    
    # Clean up expired entries in the registry to prevent memory growth
    expired_tokens = [k for k, v in USED_SIGNATURES_REGISTRY.items() if current_time > v]
    for k in expired_tokens:
        USED_SIGNATURES_REGISTRY.pop(k, None)
        
    return json.dumps({
        "status": "AUTHORIZED",
        "student_id": clean_id,
        "validated_action": clean_action,
        "security_clearance": "BIOMETRIC_HUMAN_PRESENCE_CONFIRMED",
        "gcode_actuation_command": "G1 X180.0 F500.0" # Maps safely to physical motor
    })

if __name__ == "__main__":
    import time
    time.sleep(0.5)
    mcp.run(transport='stdio')