# 🔐 Password Security Toolkit

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Security](https://img.shields.io/badge/security-educational-orange.svg)

A comprehensive password security toolkit featuring advanced strength analysis, secure password generation, and educational password management. Perfect for learning about password security and cryptographic best practices.

## ✨ Features

### 🔍 Password Analysis
- **Advanced Strength Scoring** - Multi-factor analysis (length, complexity, patterns)
- **Entropy Calculation** - Shannon entropy measurement in bits
- **Crack Time Estimation** - Realistic brute-force attack timeline
- **Pattern Detection** - Identifies weak patterns (sequences, keyboard patterns, repetitions)
- **Common Password Database** - Checks against known weak passwords
- **Detailed Feedback** - Actionable suggestions for improvement

### 🎲 Password Generation
- **Secure Random Generation** - Uses Python's `secrets` module (cryptographically secure)
- **Customizable Options** - Control length, character types, ambiguous characters
- **Passphrase Generator** - Memorable Diceware-style passphrases
- **Auto-Strength Verification** - Generated passwords automatically analyzed

### 🔒 Cryptographic Tools
- **Multiple Hash Algorithms** - MD5, SHA-1, SHA-256, SHA-512
- **Hash Verification** - Compare passwords against hashes
- **Salt Support** - Optional salt for enhanced security
- **Algorithm Detection** - Automatically identify hash algorithm

### 💾 Password Vault (Demo)
- **Secure Storage** - Stores only password hashes, never plaintext
- **SQLite Backend** - Lightweight database storage
- **Entry Management** - Add, view, and delete entries
- **Educational Purpose** - Demonstrates secure storage principles

## 📋 Requirements

- Python 3.8 or higher
- No external dependencies (uses only Python standard library)

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/vasttiono/password-security-toolkit.git
cd password-security-toolkit

# Run the application
python password_checker.py
```

## 💻 Usage

### Interactive Menu

Run the program to access the interactive menu:

```bash
python password_checker.py
```

**Available Options:**
1. Analyze Password Strength
2. Generate Secure Password
3. Generate Passphrase
4. Hash Password
5. Verify Password Hash
6. Save Password to Vault
7. View Saved Passwords
8. Delete Vault Entry
0. Exit

### Command Examples

#### Example 1: Analyze Password Strength

```
Select option: 1
Enter password to analyze: MyP@ssw0rd2024!

============================================================
PASSWORD STRENGTH ANALYSIS
============================================================

🟢 Strength: VERY STRONG
   Excellent password! Very secure.

📊 Score: 8/8
🔢 Entropy: 84.65 bits
⏱️  Estimated Crack Time: 584,942 years

📋 DETAILED FEEDBACK:
  ✅ Excellent length
  ✅ Contains lowercase letters
  ✅ Contains uppercase letters
  ✅ Contains numbers
  ✅ Contains special characters
============================================================
```

#### Example 2: Generate Secure Password

```
Select option: 2

--- PASSWORD GENERATION OPTIONS ---
Length (default 16): 20
Include special characters? (Y/n): y
Exclude ambiguous characters? (y/N): y

🔐 Generated Password: xK9@mP2$qL5#nR8!wT4%

✅ Strength: VERY STRONG
📊 Score: 8/8
```

#### Example 3: Generate Passphrase

```
Select option: 3
Number of words (default 4): 5

🔐 Generated Passphrase: Crystal-Phoenix-Mountain-Thunder-Swift-73

✅ Strength: VERY STRONG
```

## 📊 Password Strength Scoring

### Scoring Criteria

| Factor | Max Points | Criteria |
|--------|-----------|----------|
| **Length** | 3 | 16+ chars (3), 12-15 chars (2), 8-11 chars (1) |
| **Complexity** | 5 | Lowercase (1), Uppercase (1), Numbers (1), Special (2) |
| **Penalties** | -4 | Common password (-3), Patterns (-1 each) |

### Strength Levels

| Score | Level | Description | Security |
|-------|-------|-------------|----------|
| 8 | 🟢 VERY STRONG | Excellent password! | Highly secure |
| 6-7 | 🔵 STRONG | Good password | Secure |
| 4-5 | 🟡 MODERATE | Acceptable | Moderately secure |
| 2-3 | 🟠 WEAK | Vulnerable | Easily cracked |
| 0-1 | 🔴 VERY WEAK | Dangerous! | Extremely weak |

## 🔢 Understanding Entropy

**Entropy** measures password unpredictability in bits. Higher entropy = stronger password.

| Entropy (bits) | Strength | Crack Time* |
|----------------|----------|-------------|
| < 28 | Very Weak | Instant |
| 28-35 | Weak | Minutes |
| 36-59 | Fair | Days |
| 60-127 | Strong | Years |
| 128+ | Very Strong | Centuries |

*Assuming 1 billion guesses per second

## 🛡️ Security Features

### Password Generation Security
- Uses `secrets` module (cryptographically secure PRNG)
- Guaranteed character diversity
- Shuffle algorithm prevents patterns
- No predictable sequences

### Hash Security
- Supports modern algorithms (SHA-256, SHA-512)
- Optional salt support
- Secure comparison methods
- Educational demonstration of hashing

### Storage Security
- **Never stores plaintext passwords**
- Stores only cryptographic hashes
- SQLite database with proper schema
- Timestamps for audit trail

## ⚠️ Important Disclaimers

### 🚨 Educational Purpose Only

This tool is designed for:
- Learning about password security
- Understanding cryptographic concepts
- Educational demonstrations
- Security awareness training

### 🚫 Not for Production Use

**DO NOT use the vault feature for real passwords because:**
- Simplified implementation
- No encryption at rest
- No master password protection
- No secure key management
- Demo-grade security only

### ✅ For Real Password Management, Use:
- [Bitwarden](https://bitwarden.com/)
- [1Password](https://1password.com/)
- [KeePassXC](https://keepassxc.org/)
- [LastPass](https://www.lastpass.com/)

## 📁 Project Structure

```
password-security-toolkit/
│
├── password_checker.py      # Main application
├── README.md               # This file
├── LICENSE                 # MIT License
├── .gitignore             # Git ignore rules
├── requirements.txt       # Python dependencies
└── password_vault.db      # SQLite database (created on first run)
```

## 🧪 Testing

Run built-in tests:

```bash
python -m doctest password_checker.py -v
```

Or use pytest:

```bash
pip install pytest
pytest test_password_checker.py
```

## 📚 Educational Topics Covered

This project demonstrates:

1. **Password Security Principles**
   - Strength vs complexity
   - Entropy and randomness
   - Attack vectors (brute force, dictionary)

2. **Cryptography Basics**
   - Hash functions
   - Salt and pepper
   - One-way functions

3. **Python Security**
   - `secrets` module for CSPRNG
   - `hashlib` for cryptographic hashing
   - Secure coding practices

4. **Database Security**
   - Never store plaintext passwords
   - Hash storage principles
   - SQL injection prevention

## 🎓 Learning Resources

- [OWASP Password Guidelines](https://owasp.org/www-project-proactive-controls/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)
- [How Secure Is My Password](https://www.security.org/how-secure-is-my-password/)
- [Have I Been Pwned](https://haveibeenpwned.com/)

## 🔧 Advanced Usage

### Using as a Python Module

```python
from password_checker import PasswordStrengthAnalyzer, SecurePasswordGenerator

# Analyze password programmatically
analyzer = PasswordStrengthAnalyzer()
result = analyzer.analyze("MySecureP@ssw0rd!")

print(f"Strength: {result['strength']['level']}")
print(f"Entropy: {result['entropy']} bits")
print(f"Crack time: {result['crack_time']}")

# Generate password programmatically
generator = SecurePasswordGenerator()
password = generator.generate_password(length=20, use_special=True)
print(f"Generated: {password}")

# Generate passphrase
passphrase = generator.generate_passphrase(num_words=5)
print(f"Passphrase: {passphrase}")
```

### Integration Examples

**Web Application Integration:**
```python
# Flask API endpoint example
from flask import Flask, request, jsonify
from password_checker import PasswordStrengthAnalyzer

app = Flask(__name__)

@app.route('/check-password', methods=['POST'])
def check_password():
    password = request.json.get('password')
    analyzer = PasswordStrengthAnalyzer()
    result = analyzer.analyze(password)
    return jsonify(result)
```

**Batch Password Analysis:**
```python
# Analyze multiple passwords from file
with open('passwords.txt', 'r') as f:
    passwords = f.readlines()

analyzer = PasswordStrengthAnalyzer()
for pwd in passwords:
    result = analyzer.analyze(pwd.strip())
    print(f"{pwd.strip()}: {result['strength']['level']}")
```

## 🐛 Troubleshooting

### Common Issues

**Issue: Database locked error**
```bash
Solution: Close all other instances of the program
```

**Issue: Module not found**
```bash
Solution: Ensure you're running Python 3.8+
python --version
```

**Issue: Permission denied on database file**
```bash
Solution: Check file permissions
chmod 644 password_vault.db
```

## 🚀 Future Enhancements

- [ ] Password breach checker (Have I Been Pwned API integration)
- [ ] Master password protection for vault
- [ ] AES encryption for stored passwords
- [ ] Password strength meter visualization
- [ ] Export vault to encrypted file
- [ ] Two-factor authentication demo
- [ ] Password policy generator
- [ ] GUI interface with Tkinter
- [ ] Web interface with Flask
- [ ] Password generator browser extension
- [ ] Multi-language support
- [ ] Zxcvbn integration for better analysis

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute
- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the repository

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style
- Follow PEP 8 guidelines
- Add docstrings to functions
- Include type hints where appropriate
- Write unit tests for new features

## 📊 Project Statistics

- **Lines of Code**: ~700
- **Functions/Methods**: 25+
- **Classes**: 4
- **Supported Hash Algorithms**: 4
- **Password Patterns Detected**: 5+
- **Common Passwords Database**: 24+

## 🏆 Skills Demonstrated

This project showcases:

### Technical Skills
- ✅ Python programming
- ✅ Object-oriented design
- ✅ Cryptography fundamentals
- ✅ Database management (SQLite)
- ✅ Security best practices
- ✅ Algorithm implementation
- ✅ User interface design
- ✅ Error handling

### Cybersecurity Skills
- ✅ Password security analysis
- ✅ Threat modeling
- ✅ Cryptographic hashing
- ✅ Entropy calculation
- ✅ Attack vector understanding
- ✅ Secure storage principles

## 📱 Screenshots

### Main Menu
```
╔════════════════════════════════════════════════════╗
║     PASSWORD SECURITY TOOLKIT v1.0                 ║
║     Advanced Password Analysis & Generation        ║
╚════════════════════════════════════════════════════╝

============================================================
MAIN MENU
============================================================
1. Analyze Password Strength
2. Generate Secure Password
3. Generate Passphrase
4. Hash Password
5. Verify Password Hash
6. Save Password to Vault
7. View Saved Passwords
8. Delete Vault Entry
0. Exit
============================================================
```

### Analysis Output
```
============================================================
PASSWORD STRENGTH ANALYSIS
============================================================

🟢 Strength: VERY STRONG
   Excellent password! Very secure.

📊 Score: 8/8
🔢 Entropy: 84.65 bits
⏱️  Estimated Crack Time: 584,942 years

📋 DETAILED FEEDBACK:
  ✅ Excellent length
  ✅ Contains lowercase letters
  ✅ Contains uppercase letters
  ✅ Contains numbers
  ✅ Contains special characters
============================================================
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### What This Means:
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No warranty provided
- ⚠️ No liability accepted

## 👤 Author

**[Mohammad Andhika Vasttiono Hanggara]**
- GitHub: [@vasttiono](https://github.com/vasttiono)
- LinkedIn: https://www.linkedin.com/in/vasttiono


## 🙏 Acknowledgments

- Inspired by [zxcvbn](https://github.com/dropbox/zxcvbn) password strength estimator
- Password patterns based on OWASP guidelines
- Security principles from NIST standards
- Thanks to the open-source security community
- Built with ❤️ for cybersecurity education

## 📖 Related Projects

If you found this useful, check out these related projects:

- [network-port-scanner](https://github.com/vasttiono/network-port-scanner) - Network security scanner
- [sql-injection-demo](https://github.com/vasttiono/sql-injection-demo) - SQL injection educational tool
- [crypto-toolkit](https://github.com/vasttiono/crypto-toolkit) - Encryption/decryption utilities

## 🌟 Support

If you find this project helpful:
- ⭐ Star this repository
- 🔗 Share with others
- 🐛 Report issues
- 💬 Provide feedback

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/vasttiono/password-security-toolkit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vasttiono/password-security-toolkit/discussions)
- **Security Issues**: Email directly (do not open public issue)

## ⚖️ Disclaimer

This software is provided "as is" without warranty of any kind. The authors are not responsible for any damage or loss resulting from the use of this software. Always follow ethical guidelines and legal requirements when working with security tools.

---

<div align="center">

**🔐 Security First • 🎓 Education Focused • 💻 Open Source**

Made with ❤️ for the cybersecurity community

[Report Bug](https://github.com/vasttiono/password-security-toolkit/issues) · [Request Feature](https://github.com/vasttiono/password-security-toolkit/issues) · [Documentation](https://github.com/vasttiono/password-security-toolkit/wiki)

</div>