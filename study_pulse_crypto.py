import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = Path("study_pulse.key")
DATA_FILE = Path("encrypted_study_note.json")

def load_or_create_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    
    new_key = AESGCM.generate_key(bit_length=256)
    KEY_FILE.write_bytes(new_key)
    return new_key

def encrypt_note(my_note, secret_key):
    if not my_note.strip():
        raise ValueError("Note cannot be empty!")
    
    aes_gcm = AESGCM(secret_key)
    nonce = os.urandom(12)
    
    ciphertext = aes_gcm.encrypt(nonce, my_note.encode("utf-8"), None)
    
    saved_data = {
        "algorithm": "AES-256-GCM",
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }
    
    DATA_FILE.write_text(json.dumps(saved_data, indent=2), encoding="utf-8")
    return saved_data

def decrypt_note(json_data, secret_key):
    aes_gcm = AESGCM(secret_key)
    
    my_nonce = bytes.fromhex(json_data["nonce"])
    my_ciphertext = bytes.fromhex(json_data["ciphertext"])
    
    decrypted_bytes = aes_gcm.decrypt(my_nonce, my_ciphertext, None)
    return decrypted_bytes.decode("utf-8")