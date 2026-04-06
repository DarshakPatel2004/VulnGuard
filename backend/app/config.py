# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
import base64
from dotenv import load_dotenv

# Load .env at module level
load_dotenv()

def get_config(key: str, default: str = "") -> str:
    """
    Retrieve an environment variable and automatically decode it
    if it's prefixed with 'b64:'.
    """
    value = os.getenv(key, default)
    if value and value.startswith("b64:"):
        try:
            # Strip the prefix and decode
            encoded_part = value[4:]
            decoded_bytes = base64.b64decode(encoded_part)
            return decoded_bytes.decode("utf-8")
        except Exception as e:
            # Fallback to original value if decoding fails
            print(f"Error decoding config key '{key}': {e}")
            return value
    return value


def auto_obfuscate():
    """
    Automatically scan the .env file and encode sensitive keys if they
    are currently in plain-text. This allows 'set and forget' obfuscation.
    """
    env_path = ".env"
    if not os.path.exists(env_path):
        return

    keys_to_encode = [
        "NVD_API_KEY",
        "OTX_API_KEY",
        "BASIC_AUTH_USERNAME",
        "BASIC_AUTH_PASSWORD"
    ]

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        updated = False
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                new_lines.append(line)
                continue

            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key in keys_to_encode and value and not value.startswith("b64:"):
                # Encode the value
                encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")
                new_lines.append(f"{key}=b64:{encoded_value}\n")
                updated = True
            else:
                new_lines.append(line)

        if updated:
            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            print(f"[Config] Automated obfuscation complete: sensitive keys in {env_path} have been encoded.")
    except Exception as e:
        print(f"[Config] Shared error during auto-obfuscation: {e}")
