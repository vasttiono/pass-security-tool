"""
Password Security Toolkit
A comprehensive tool for password analysis, generation, and security assessment
Author: [Your Name]
Version: 1.0
"""

import re
import secrets
import string
import hashlib
import sqlite3
from datetime import datetime
import math
import sys


class PasswordStrengthAnalyzer:
    """Advanced password strength analysis with entropy calculation"""
    
    # Common weak passwords database
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
        'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
        '123123', '654321', 'superman', 'qazwsx', 'michael', 'football'
    }
    
    # Common patterns to detect
    PATTERNS = {
        'sequential_numbers': r'(012|123|234|345|456|567|678|789|890)',
        'sequential_letters': r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
        'keyboard_patterns': r'(qwerty|asdfgh|zxcvbn|qwertz)',
        'repeated_chars': r'(.)\1{2,}'
    }
    
    def __init__(self):
        self.score = 0
        self.feedback = []
        self.warnings = []
        self.suggestions = []
    
    def calculate_entropy(self, password):
        """
        Calculate Shannon entropy of password
        Higher entropy = more unpredictable = stronger password
        """
        charset_size = 0
        
        # Determine character set size
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            charset_size += 33
        
        if charset_size == 0:
            return 0
        
        # Entropy = length × log2(charset_size)
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def check_common_patterns(self, password):
        """Check for common weak patterns"""
        password_lower = password.lower()
        
        # Check for common passwords
        if password_lower in self.COMMON_PASSWORDS:
            self.warnings.append("🚨 This is a commonly used password - VERY WEAK!")
            self.score -= 3
            return True
        
        # Check for patterns
        for pattern_name, pattern_regex in self.PATTERNS.items():
            if re.search(pattern_regex, password_lower):
                self.warnings.append(f"⚠️  Contains {pattern_name.replace('_', ' ')}")
                self.score -= 1
        
        return False
    
    def analyze_length(self, password):
        """Analyze password length"""
        length = len(password)
        
        if length < 8:
            self.feedback.append("❌ Too short - minimum 8 characters required")
            self.suggestions.append("💡 Use at least 12 characters for better security")
            return 0
        elif length < 12:
            self.feedback.append("⚠️  Length is acceptable but not ideal")
            self.suggestions.append("💡 Consider using 12+ characters")
            return 1
        elif length < 16:
            self.feedback.append("✅ Good length")
            return 2
        else:
            self.feedback.append("✅ Excellent length")
            return 3
    
    def analyze_complexity(self, password):
        """Analyze character complexity"""
        complexity_score = 0
        
        if re.search(r'[a-z]', password):
            self.feedback.append("✅ Contains lowercase letters")
            complexity_score += 1
        else:
            self.feedback.append("❌ Missing lowercase letters")
            self.suggestions.append("💡 Add lowercase letters (a-z)")
        
        if re.search(r'[A-Z]', password):
            self.feedback.append("✅ Contains uppercase letters")
            complexity_score += 1
        else:
            self.feedback.append("❌ Missing uppercase letters")
            self.suggestions.append("💡 Add uppercase letters (A-Z)")
        
        if re.search(r'[0-9]', password):
            self.feedback.append("✅ Contains numbers")
            complexity_score += 1
        else:
            self.feedback.append("❌ Missing numbers")
            self.suggestions.append("💡 Add numbers (0-9)")
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            self.feedback.append("✅ Contains special characters")
            complexity_score += 2
        else:
            self.feedback.append("⚠️  Missing special characters")
            self.suggestions.append("💡 Add special characters (!@#$%^&*)")
        
        return complexity_score
    
    def calculate_crack_time(self, entropy):
        """Estimate time to crack password (assuming 1 billion attempts/second)"""
        possible_combinations = 2 ** entropy
        attempts_per_second = 1_000_000_000  # 1 billion
        
        seconds = possible_combinations / (attempts_per_second * 2)  # Average case
        
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} days"
        else:
            years = int(seconds / 31536000)
            if years > 1_000_000_000:
                return "Billions of years"
            elif years > 1_000_000:
                return f"{years / 1_000_000:.1f} million years"
            else:
                return f"{years:,} years"
    
    def get_strength_level(self, score):
        """Determine overall strength level"""
        if score >= 8:
            return {
                'level': 'VERY STRONG',
                'color': '🟢',
                'description': 'Excellent password! Very secure.'
            }
        elif score >= 6:
            return {
                'level': 'STRONG',
                'color': '🔵',
                'description': 'Good password with solid security.'
            }
        elif score >= 4:
            return {
                'level': 'MODERATE',
                'color': '🟡',
                'description': 'Acceptable but could be improved.'
            }
        elif score >= 2:
            return {
                'level': 'WEAK',
                'color': '🟠',
                'description': 'This password is vulnerable to attacks.'
            }
        else:
            return {
                'level': 'VERY WEAK',
                'color': '🔴',
                'description': 'DANGER! This password is easily cracked.'
            }
    
    def analyze(self, password):
        """Complete password analysis"""
        # Reset state
        self.score = 0
        self.feedback = []
        self.warnings = []
        self.suggestions = []
        
        # Run checks
        is_common = self.check_common_patterns(password)
        
        if not is_common:
            length_score = self.analyze_length(password)
            complexity_score = self.analyze_complexity(password)
            self.score = length_score + complexity_score
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        crack_time = self.calculate_crack_time(entropy)
        
        # Get strength level
        strength = self.get_strength_level(self.score)
        
        return {
            'score': max(0, self.score),
            'max_score': 8,
            'strength': strength,
            'entropy': entropy,
            'crack_time': crack_time,
            'feedback': self.feedback,
            'warnings': self.warnings,
            'suggestions': self.suggestions
        }


class SecurePasswordGenerator:
    """Generate cryptographically secure passwords"""
    
    @staticmethod
    def generate_password(length=16, use_uppercase=True, use_numbers=True, 
                         use_special=True, exclude_ambiguous=False):
        """
        Generate a secure random password
        
        Args:
            length: Password length (minimum 8)
            use_uppercase: Include uppercase letters
            use_numbers: Include numbers
            use_special: Include special characters
            exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, etc.)
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        # Build character set
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        numbers = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            lowercase = lowercase.replace('l', '').replace('o', '')
            uppercase = uppercase.replace('I', '').replace('O', '')
            numbers = numbers.replace('0', '').replace('1', '')
            special = special.replace('|', '')
        
        # Build character pool
        chars = lowercase
        required_chars = [secrets.choice(lowercase)]
        
        if use_uppercase:
            chars += uppercase
            required_chars.append(secrets.choice(uppercase))
        
        if use_numbers:
            chars += numbers
            required_chars.append(secrets.choice(numbers))
        
        if use_special:
            chars += special
            required_chars.append(secrets.choice(special))
        
        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [
            secrets.choice(chars) for _ in range(remaining_length)
        ]
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    @staticmethod
    def generate_passphrase(num_words=4, separator='-', capitalize=True):
        """Generate memorable passphrase (Diceware-style)"""
        # Simple word list (in production, use a proper wordlist)
        words = [
            'apple', 'ocean', 'mountain', 'sunset', 'forest', 'river',
            'cloud', 'thunder', 'crystal', 'phoenix', 'dragon', 'tiger',
            'silver', 'golden', 'purple', 'cosmic', 'bright', 'swift',
            'strong', 'brave', 'noble', 'wise', 'free', 'wild'
        ]
        
        selected_words = [secrets.choice(words) for _ in range(num_words)]
        
        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]
        
        # Add random number for extra security
        random_num = secrets.randbelow(100)
        
        passphrase = separator.join(selected_words) + separator + str(random_num)
        
        return passphrase


class PasswordHasher:
    """Password hashing and verification utilities"""
    
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']
    
    @staticmethod
    def hash_password(password, algorithm='sha256', salt=None):
        """Hash password with optional salt"""
        if algorithm not in PasswordHasher.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm. Use: {PasswordHasher.SUPPORTED_ALGORITHMS}")
        
        # Add salt if provided
        password_bytes = password.encode('utf-8')
        if salt:
            password_bytes = salt.encode('utf-8') + password_bytes
        
        # Hash
        if algorithm == 'md5':
            return hashlib.md5(password_bytes).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(password_bytes).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password_bytes).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(password_bytes).hexdigest()
    
    @staticmethod
    def verify_hash(password, hash_value, algorithm=None):
        """Verify password against hash"""
        if algorithm:
            computed_hash = PasswordHasher.hash_password(password, algorithm)
            return computed_hash.lower() == hash_value.lower()
        else:
            # Try all algorithms
            for algo in PasswordHasher.SUPPORTED_ALGORITHMS:
                if PasswordHasher.verify_hash(password, hash_value, algo):
                    return True, algo
            return False, None


class PasswordVault:
    """Simple password storage demo (educational purposes only)"""
    
    def __init__(self, db_path='password_vault.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_password(self, service, username, password, algorithm='sha256'):
        """Save password (stores hash, not plaintext)"""
        password_hash = PasswordHasher.hash_password(password, algorithm)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO passwords (service, username, password_hash, algorithm)
            VALUES (?, ?, ?, ?)
        ''', (service, username, password_hash, algorithm))
        
        conn.commit()
        conn.close()
        
        return True
    
    def list_entries(self):
        """List all stored entries (without passwords)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, service, username, created_at 
            FROM passwords 
            ORDER BY created_at DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def delete_entry(self, entry_id):
        """Delete entry by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        return affected > 0


def print_header():
    """Print application header"""
    header = """
    ╔════════════════════════════════════════════════════╗
    ║     PASSWORD SECURITY TOOLKIT v1.0                 ║
    ║     Advanced Password Analysis & Generation        ║
    ╚════════════════════════════════════════════════════╝
    """
    print(header)


def print_analysis_results(result):
    """Pretty print analysis results"""
    print("\n" + "="*60)
    print("PASSWORD STRENGTH ANALYSIS")
    print("="*60)
    
    strength = result['strength']
    print(f"\n{strength['color']} Strength: {strength['level']}")
    print(f"   {strength['description']}")
    print(f"\n📊 Score: {result['score']}/{result['max_score']}")
    print(f"🔢 Entropy: {result['entropy']} bits")
    print(f"⏱️  Estimated Crack Time: {result['crack_time']}")
    
    if result['warnings']:
        print(f"\n{'⚠️  WARNINGS:':^60}")
        for warning in result['warnings']:
            print(f"  {warning}")
    
    if result['feedback']:
        print(f"\n{'📋 DETAILED FEEDBACK:':^60}")
        for feedback in result['feedback']:
            print(f"  {feedback}")
    
    if result['suggestions']:
        print(f"\n{'💡 SUGGESTIONS:':^60}")
        for suggestion in result['suggestions']:
            print(f"  {suggestion}")
    
    print("="*60 + "\n")


def main_menu():
    """Display main menu"""
    print("\n" + "="*60)
    print("MAIN MENU")
    print("="*60)
    print("1. Analyze Password Strength")
    print("2. Generate Secure Password")
    print("3. Generate Passphrase")
    print("4. Hash Password")
    print("5. Verify Password Hash")
    print("6. Save Password to Vault")
    print("7. View Saved Passwords")
    print("8. Delete Vault Entry")
    print("0. Exit")
    print("="*60)


def main():
    """Main application loop"""
    print_header()
    
    analyzer = PasswordStrengthAnalyzer()
    generator = SecurePasswordGenerator()
    vault = PasswordVault()
    
    while True:
        try:
            main_menu()
            choice = input("\nSelect option (0-8): ").strip()
            
            if choice == '0':
                print("\n👋 Thank you for using Password Security Toolkit!")
                sys.exit(0)
            
            elif choice == '1':
                password = input("\nEnter password to analyze: ")
                result = analyzer.analyze(password)
                print_analysis_results(result)
                input("\nPress Enter to continue...")
            
            elif choice == '2':
                print("\n--- PASSWORD GENERATION OPTIONS ---")
                length = int(input("Length (default 16): ") or "16")
                use_special = input("Include special characters? (Y/n): ").lower() != 'n'
                exclude_ambiguous = input("Exclude ambiguous characters? (y/N): ").lower() == 'y'
                
                password = generator.generate_password(
                    length=length,
                    use_special=use_special,
                    exclude_ambiguous=exclude_ambiguous
                )
                
                print(f"\n🔐 Generated Password: {password}")
                
                # Auto-analyze
                result = analyzer.analyze(password)
                print(f"\n✅ Strength: {result['strength']['level']}")
                print(f"📊 Score: {result['score']}/{result['max_score']}")
                
                input("\nPress Enter to continue...")
            
            elif choice == '3':
                num_words = int(input("\nNumber of words (default 4): ") or "4")
                passphrase = generator.generate_passphrase(num_words=num_words)
                
                print(f"\n🔐 Generated Passphrase: {passphrase}")
                
                result = analyzer.analyze(passphrase)
                print(f"\n✅ Strength: {result['strength']['level']}")
                
                input("\nPress Enter to continue...")
            
            elif choice == '4':
                password = input("\nEnter password to hash: ")
                print("\nAvailable algorithms: md5, sha1, sha256, sha512")
                algorithm = input("Select algorithm (default sha256): ") or "sha256"
                
                hash_value = PasswordHasher.hash_password(password, algorithm)
                
                print(f"\n{algorithm.upper()} Hash:")
                print(hash_value)
                
                input("\nPress Enter to continue...")
            
            elif choice == '5':
                password = input("\nEnter password: ")
                hash_value = input("Enter hash to verify: ")
                
                is_valid, detected_algo = PasswordHasher.verify_hash(password, hash_value)
                
                if is_valid:
                    print(f"\n✅ Password MATCHES! (Algorithm: {detected_algo.upper()})")
                else:
                    print("\n❌ Password DOES NOT MATCH!")
                
                input("\nPress Enter to continue...")
            
            elif choice == '6':
                print("\n--- SAVE TO VAULT ---")
                service = input("Service/Website name: ")
                username = input("Username/Email: ")
                password = input("Password: ")
                
                vault.save_password(service, username, password)
                print("\n✅ Password saved successfully!")
                print("⚠️  Note: Only hash is stored, not plaintext password")
                
                input("\nPress Enter to continue...")
            
            elif choice == '7':
                entries = vault.list_entries()
                
                print("\n" + "="*60)
                print("SAVED PASSWORDS")
                print("="*60)
                
                if entries:
                    print(f"{'ID':<5} {'Service':<20} {'Username':<20} {'Date'}")
                    print("-"*60)
                    for entry in entries:
                        print(f"{entry[0]:<5} {entry[1]:<20} {entry[2]:<20} {entry[3][:10]}")
                else:
                    print("No passwords saved yet.")
                
                print("="*60)
                input("\nPress Enter to continue...")
            
            elif choice == '8':
                entry_id = int(input("\nEnter ID to delete: "))
                
                if vault.delete_entry(entry_id):
                    print("\n✅ Entry deleted successfully!")
                else:
                    print("\n❌ Entry not found!")
                
                input("\nPress Enter to continue...")
            
            else:
                print("\n❌ Invalid option! Please select 0-8.")
                input("\nPress Enter to continue...")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()