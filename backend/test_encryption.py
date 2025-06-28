#!/usr/bin/env python3
"""
Test script to verify the encryption system works correctly.
"""

import os
from cryptography.fernet import Fernet

def test_encryption():
    print("🔐 Testing Encryption System")
    print("=" * 30)
    
    # Generate a test key
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Test data
    test_api_key = "test-google-ai-api-key-12345"
    
    # Encrypt
    encrypted = cipher.encrypt(test_api_key.encode())
    print(f"✅ Original: {test_api_key}")
    print(f"✅ Encrypted: {encrypted.decode()}")
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted).decode()
    print(f"✅ Decrypted: {decrypted}")
    
    # Verify
    if test_api_key == decrypted:
        print("✅ Encryption/Decryption test PASSED!")
        return True
    else:
        print("❌ Encryption/Decryption test FAILED!")
        return False

def test_config_import():
    print("\n📋 Testing Config Import")
    print("=" * 30)
    
    try:
        from config import secure_config
        print("✅ Config import successful")
        
        # Test encryption/decryption
        test_key = "test-key-123"
        encrypted = secure_config.encrypt(test_key)
        decrypted = secure_config.decrypt(encrypted)
        
        if test_key == decrypted:
            print("✅ Config encryption test PASSED!")
            return True
        else:
            print("❌ Config encryption test FAILED!")
            return False
            
    except Exception as e:
        print(f"❌ Config import failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Running Encryption Tests\n")
    
    test1 = test_encryption()
    test2 = test_config_import()
    
    print(f"\n📊 Test Results:")
    print(f"Basic Encryption: {'✅ PASS' if test1 else '❌ FAIL'}")
    print(f"Config System: {'✅ PASS' if test2 else '❌ FAIL'}")
    
    if test1 and test2:
        print("\n🎉 All tests passed! Encryption system is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Please check the configuration.") 