#!/usr/bin/env python3
"""
Utility script to encrypt API keys for secure storage.
This script helps you encrypt your API keys so they can be safely stored in environment variables.
"""

import os
import base64
from cryptography.fernet import Fernet

def generate_encryption_key():
    """Generate a new encryption key"""
    key = Fernet.generate_key()
    return key.decode()

def encrypt_api_key(api_key, encryption_key):
    """Encrypt an API key"""
    if not api_key:
        return None
    
    cipher = Fernet(encryption_key.encode())
    encrypted_key = cipher.encrypt(api_key.encode())
    return encrypted_key.decode()

def main():
    print("🔐 API Key Encryption Utility")
    print("=" * 40)
    
    # Check if .env file exists
    env_file = '.env'
    env_exists = os.path.exists(env_file)
    
    # Check if encryption key exists
    encryption_key = None
    if env_exists:
        with open(env_file, 'r') as f:
            for line in f:
                if line.startswith('ENCRYPTION_KEY='):
                    encryption_key = line.split('=', 1)[1].strip()
                    break
    
    if not encryption_key:
        print("No encryption key found. Generating a new one...")
        encryption_key = generate_encryption_key()
        print(f"\n🔑 Generated encryption key: {encryption_key}")
        print("\n⚠️  IMPORTANT: Save this key securely! You'll need it to decrypt your API keys.")
        
        # Ask if user wants to save it to .env
        save_key = input("\nWould you like to save this key to .env file? (y/n): ").lower().strip()
        if save_key == 'y':
            with open(env_file, 'a') as f:
                f.write(f"ENCRYPTION_KEY={encryption_key}\n")
            print("✅ Encryption key saved to .env file")
    else:
        print(f"🔑 Found existing encryption key: {encryption_key[:20]}...")
    
    # Get API keys from user
    print("\n📝 Enter your API keys (press Enter to skip):")
    
    google_ai_key = input("Google AI Studio API Key: ").strip()
    openai_key = input("OpenAI API Key: ").strip()
    
    # Encrypt the keys
    encrypted_keys = {}
    
    if google_ai_key:
        encrypted_google = encrypt_api_key(google_ai_key, encryption_key)
        encrypted_keys['GOOGLE_AI_API_KEY_ENCRYPTED'] = encrypted_google
        print("✅ Google AI API key encrypted")
    
    if openai_key:
        encrypted_openai = encrypt_api_key(openai_key, encryption_key)
        encrypted_keys['OPENAI_API_KEY_ENCRYPTED'] = encrypted_openai
        print("✅ OpenAI API key encrypted")
    
    if not encrypted_keys:
        print("❌ No API keys provided")
        return
    
    # Save encrypted keys to .env
    print("\n💾 Saving encrypted keys to .env file...")
    with open(env_file, 'a') as f:
        for key_name, encrypted_value in encrypted_keys.items():
            f.write(f"{key_name}={encrypted_value}\n")
    
    print("✅ Encrypted API keys saved to .env file")
    print("\n🔒 Your API keys are now encrypted and safe for public repositories!")
    print("\n📋 Next steps:")
    print("1. Add .env to your .gitignore file (already done)")
    print("2. Share the ENCRYPTION_KEY securely with your team")
    print("3. The application will automatically decrypt the keys at runtime")
    print("\n🔑 Your encryption key (save this securely):")
    print(f"ENCRYPTION_KEY={encryption_key}")

if __name__ == "__main__":
    main() 