# src/main_server.py
import os
import sys
import json
import hmac
import hashlib
import time
import threading

# Force the project root directory into the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("SEOSiri-Biometric-IoT-Guard")

# Try to import paho-mqtt silently to maintain local-first fallback integrity
try:
    import paho.mqtt.client as mqtt # Requires: pip install paho-mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

# Shared cryptographic key used by the Flutter app's token generator
SHARED_DEVICE_KEY = b"seosiri_biometric_iot_secret_2026"

# Anti-Replay Registry: Keeps track of used signatures within the 5-minute window
USED_SIGNATURES_REGISTRY = {}

# Active verified sessions memory (representing verified human presence)
ACTIVE_SESSIONS = {}

# Helper: Pure cryptographic token verification
def execute_token_verification(student_id: str, biometric_token: str, action_subject: str, timestamp_epoch: int) -> dict:
    clean_id = student_id.strip().lower()
    clean_action = action_subject.strip().lower()
    token = biometric_token.strip().lower()
    
    # 1. Temporal Check
    current_time = int(time.time())
    if abs(current_time - timestamp_epoch) > 300:
        return {"status": "REJECTED", "reason": "TEMPORAL_WINDOW_VIOLATION"}
        
    # 2. Anti-Replay Check
    if token in USED_SIGNATURES_REGISTRY:
        return {"status": "REJECTED", "reason": "SIGNATURE_REUSE_DETECTED"}
        
    # 3. Cryptographic Signature Check
    payload = f"{clean_id}:{clean_action}:{timestamp_epoch}".encode('utf-8')
    expected_token = hmac.new(SHARED_DEVICE_KEY, payload, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_token, token):
        return {"status": "REJECTED", "reason": "CRYPTOGRAPHIC_SIGNATURE_MISMATCH"}
        
    # 4. Commit to registries
    USED_SIGNATURES_REGISTRY[token] = current_time + 300
    ACTIVE_SESSIONS[clean_id] = {"action": clean_action, "expires_at": current_time + 300}
    
    # Clean up expired registry entries
    expired_tokens = [k for k, v in USED_SIGNATURES_REGISTRY.items() if current_time > v]
    for k in expired_tokens:
        USED_SIGNATURES_REGISTRY.pop(k, None)
        
    return {
        "status": "AUTHORIZED",
        "student_id": clean_id,
        "validated_action": clean_action,
        "gcode_actuation_command": "G1 X180.0 F500.0"
    }

@mcp.tool()
def secure_biometric_iot_gatekeeper(student_id: str, biometric_token: str, proposed_action: str, timestamp_epoch: int) -> str:
    """
    Unified Biometric IoT Gatekeeper: Authenticates mobile biometric tokens,
    enforces strict temporal anti-replay bounds, and authorizes safe robotic actuation.
    """
    res = execute_token_verification(student_id, biometric_token, proposed_action, timestamp_epoch)
    return json.dumps(res)

@mcp.tool()
def check_active_authorizations(student_id: str) -> str:
    """
    AI Gatekeeper: Queries the active on-memory session cache to check 
    if the student has an active, validated biometric authorization.
    """
    clean_id = student_id.strip().lower()
    session = ACTIVE_SESSIONS.get(clean_id)
    
    if not session:
        return json.dumps({
            "status": "UNAUTHORIZED",
            "student_id": clean_id,
            "reason": "NO_ACTIVE_BIOMETRIC_SESSION",
            "message": "Please authenticate via the biometric_iot_bridge app on your phone."
        })
        
    current_time = int(time.time())
    if current_time > session["expires_at"]:
        ACTIVE_SESSIONS.pop(clean_id, None)
        return json.dumps({
            "status": "UNAUTHORIZED",
            "student_id": clean_id,
            "reason": "BIOMETRIC_SESSION_EXPIRED"
        })
        
    return json.dumps({
        "status": "AUTHORIZED",
        "student_id": clean_id,
        "authorized_action": session["action"],
        "expires_in_seconds": int(session["expires_at"] - current_time),
        "gcode_command": "G1 X180.0 F500.0"
    })

# =====================================================================
# BACKGROUND THREADED MQTT CLIENT LOOP (The Active Gateway)
# =====================================================================
def start_background_mqtt_listener():
    """Launches a background thread to subscribe to the live MQTT broker."""
    if not MQTT_AVAILABLE:
        print("[Gateway] paho-mqtt not installed. Background listener disabled.")
        return

    def on_connect(client, userdata, flags, rc, properties=None):
        print(f"[Gateway] Connected to MQTT broker (test.mosquitto.org) with code: {rc}")
        # Subscribe to your official bionics token topic
        client.subscribe("seosiri/biometric_iot/token")

    def on_message(client, userdata, msg):
        try:
            # Parse incoming biometric token published by the Flutter app
            data = json.loads(msg.payload.decode('utf-8'))
            student_id = data.get("student_id")
            token = data.get("biometric_token")
            action = data.get("proposed_action")
            timestamp = int(data.get("timestamp_epoch", 0))
            
            print(f"\n[Gateway] Intercepted live token for student: {student_id}")
            
            # Execute verification and cache the authorized state automatically
            res = execute_token_verification(student_id, token, action, timestamp)
            print(f"[Gateway] Handshake Verification Status: {res['status']}")
        except Exception as e:
            print(f"[Gateway Error] Failed to process incoming MQTT payload: {e}")

    # Initialize standard v2 callback client
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        # Connect to free, public MQTT Broker (test.mosquitto.org)
        client.connect("test.mosquitto.org", 1883, 60)
        client.loop_start() # Runs network loop in a background thread
        print("[Gateway] Background MQTT client loop active.")
    except Exception as e:
        print(f"[Gateway Error] Could not connect to MQTT broker: {e}")

if __name__ == "__main__":
    # Start the active background listener before running standard stdio transport
    start_background_mqtt_listener()
    
    import time
    time.sleep(0.5)
    mcp.run(transport='stdio')