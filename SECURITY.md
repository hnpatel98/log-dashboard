# 🔐 Security Configuration

This project uses encrypted API keys to ensure sensitive data is not exposed in public repositories.

## 🛡️ How It Works

The system uses **Fernet symmetric encryption** to encrypt API keys before storing them in environment variables. This allows you to:

- ✅ Store encrypted keys in public repositories safely
- ✅ Share the encryption key securely with your team
- ✅ Automatically decrypt keys at runtime
- ✅ Use multiple AI services (Google AI Studio, OpenAI)

## 🚀 Quick Setup

### 1. Run the Encryption Utility

```bash
cd backend
python encrypt_keys.py
```

### 2. Follow the Prompts

The utility will:
- Generate a secure encryption key (if none exists)
- Prompt for your API keys
- Encrypt and save them to `.env` file

### 3. Secure Your Repository

The `.gitignore` file already excludes:
- `.env` files (contains encrypted keys)
- `backend/uploads/` (user data)
- `backend/data/` (analysis results)

## 🔑 Environment Variables

### Required
- `ENCRYPTION_KEY`: Your encryption key (keep this secret!)

### Optional (encrypted)
- `GOOGLE_AI_API_KEY_ENCRYPTED`: Encrypted Google AI Studio API key
- `OPENAI_API_KEY_ENCRYPTED`: Encrypted OpenAI API key

## 📋 Manual Setup

If you prefer to set up manually:

### 1. Generate Encryption Key
```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())  # Save this securely
```

### 2. Encrypt Your API Keys
```python
from cryptography.fernet import Fernet

# Use your encryption key
cipher = Fernet(your_encryption_key.encode())

# Encrypt your API keys
google_encrypted = cipher.encrypt(google_api_key.encode()).decode()
openai_encrypted = cipher.encrypt(openai_api_key.encode()).decode()
```

### 3. Add to .env File
```bash
ENCRYPTION_KEY=your_encryption_key_here
GOOGLE_AI_API_KEY_ENCRYPTED=encrypted_google_key_here
OPENAI_API_KEY_ENCRYPTED=encrypted_openai_key_here
```

## 🔄 AI Service Priority

The system uses AI services in this order:
1. **Google AI Studio** (Gemini 1.5 Flash) - Primary
2. **OpenAI** (GPT-3.5-turbo) - Fallback
3. **Mock AI** - Rule-based recommendations

## 🛠️ Development

### Testing Encryption
```python
from config import secure_config

# Test decryption
api_key = secure_config.get_api_key('GOOGLE_AI_API_KEY')
print(f"Decrypted key: {api_key[:10]}..." if api_key else "No key found")
```

### Adding New API Keys
1. Add the key to `encrypt_keys.py`
2. Update `config.py` to include the new key
3. Update `app.py` to use the new service

## 🔒 Security Best Practices

- ✅ Never commit `.env` files to version control
- ✅ Share encryption keys securely (not in code)
- ✅ Rotate encryption keys periodically
- ✅ Use different keys for development/production
- ✅ Monitor API usage and costs

## 🚨 Troubleshooting

### "Decryption error" 
- Check that `ENCRYPTION_KEY` is correct
- Ensure encrypted keys are properly formatted

### "No API key found"
- Verify keys are encrypted and stored in `.env`
- Check that `ENCRYPTION_KEY` is set

### "API service not available"
- Verify API keys are valid
- Check API service status
- Review API quotas and billing

## 📞 Support

If you encounter issues:
1. Check the logs in `backend/app.log`
2. Verify your `.env` configuration
3. Test with the encryption utility
4. Review API service documentation 