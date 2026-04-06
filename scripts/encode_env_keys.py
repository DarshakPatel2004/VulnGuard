# ═══════════════════════════════════════════════════════════
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
import base64
import sys

def encode_keys():
    env_path = ".env"
    if not os.path.exists(env_path):
        print(f"Error: {env_path} not found.")
        return

    keys_to_encode = [
        "NVD_API_KEY",
        "OTX_API_KEY",
        "BASIC_AUTH_USERNAME",
        "BASIC_AUTH_PASSWORD"
    ]

    with open(env_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    updated = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        if "=" in stripped:
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key in keys_to_encode and not value.startswith("b64:"):
                # Encode the value
                encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")
                new_lines.append(f"{key}=b64:{encoded_value}\n")
                print(f"Encoded {key}")
                updated = True
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if updated:
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print("\nSuccess: Sensitive keys in .env have been encoded.")
    else:
        print("\nNo keys needed encoding (they might already be encoded).")

if __name__ == "__main__":
    encode_keys()
