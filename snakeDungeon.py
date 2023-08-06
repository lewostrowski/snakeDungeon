import argparse
import base64
import getpass
import hashlib
import shutil
import os
import sys
import zipfile

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Vault:
    """
    Handle zip encryption/decryption.

    Attributes:
        input_file (string): Name of a input_file to zip/unzip.
    """
    
    def __init__(self, input_file):
        """
        Initialize instance.

        Args:
            input_file (string): Name of a input_file to zip/unzip.
        """
        self.input_file = input_file

    def calculate_file_hash(self, file_path):
        """
        Calculate hashsum.

        Args:
            file_path (string): path to a file.
        """
        hash_object = hashlib.sha256()
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                hash_object.update(chunk)
                
        return hash_object.hexdigest()

    def mask(self):
        """Mask a file."""
        mask_input = int(getpass.getpass(f'[+] Mask value \033[1m{args.input_file}\033[0m: '))
        
        with open(f'{self.input_file}.bin', 'rb') as file:
            data = file.read()

        if mask_input <= 0 and mask_input >= 255:
            print(f'\033[31m\033[1m[-] Error\033[0m: wrong mask value.')
            sys.exit(1)
            
        mask_result = bytes(byte ^ mask_input for byte in data)
    
        with open(f'{self.input_file}.bin', 'wb') as file:
            file.write(mask_result)

        print(f'[+] \033[1m{self.input_file}\033[0m mask processed.')
        
    def password_processor(self, mode):
        """ Transform given password into 32 bytes length key encoded by base64."""
        # Get password & salt.
        password = getpass.getpass(f'[+] Encrypt \033[1m{args.input_file}\033[0m with password: ')
        salt = getpass.getpass(f'[+] Salt for \033[1m{args.input_file}\033[0m: ')
    
        if mode == 'encrypt':
            repeat = getpass.getpass('[+] Repeat password: ')
            if password != repeat:
                print(f'\033[31m\033[1m[-] Error\033[0m: passwords does not match')
                sys.exit(1)
            else:
                print('[+] Processing.')
                
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000
        )
        
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)
    
    
    def do_zip(self):
        """Zip input_file and remove it."""
        with zipfile.ZipFile(f'{self.input_file}.zip', 'w') as zip_me:
            for root, _, files  in os.walk(self.input_file):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_me.write(file_path)
                    
        shutil.rmtree(self.input_file)
        print(f'[+] \033[1m{self.input_file}\033[0m zipped')    
    
    def do_encryption(self):
        """Encrypt zipped input_file and remove zip file."""
        with open(f'{self.input_file}.bin', 'wb') as encrypted_file:
            # Read zip content.
            with open(f'{self.input_file}.zip', 'rb') as zip_file:
                zip_content = zip_file.read()
    
            # Encrypt zip content.
            cipher = Fernet(self.password_processor('encrypt'))
            encrypted_zip = cipher.encrypt(zip_content)
            encrypted_file.write(encrypted_zip)
            
        os.remove(f'{self.input_file}.zip')
        
        print(f'[+] \033[1m{self.input_file}\033[0m encrypted.')   
    
    def revert_zip(self):
        """Unzip archive and delete it."""
        with zipfile.ZipFile(f'{self.input_file}.zip', 'r') as revert_zipping:
            revert_zipping.extractall()
            
        os.remove(f'{self.input_file}.zip')
        print(f'[+] \033[1m{self.input_file}\033[0m unzipped')    
    
    def revert_encryption(self):
        """Decrypt binary file and delete it."""
        # Read encrypted file
        with open(f'{self.input_file}.bin', 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
            cipher = Fernet(self.password_processor('decrypt'))
            decrypted_data = cipher.decrypt(encrypted_data)

        os.remove(f'{self.input_file}.bin')
        
        # Decrypt and save as zip
        with open(f'{self.input_file}.zip', 'wb') as zip_me:
            zip_me.write(decrypted_data)

        print(f'[+] \033[1m{self.input_file}\033[0m decrypted')    


if __name__ == '__main__':
    # Parse arguments.
    parser = argparse.ArgumentParser(prog='snakeDungeon')
    
    parser.add_argument('instruction')
    parser.add_argument('input_file')
    args = parser.parse_args()

    # Init job.
    vault_instance = Vault(args.input_file)

    # Encryption.    
    if args.instruction == 'encrypt':
        #Check if target and cover image exists & ask to repeat password.
        if not os.path.exists(args.input_file):
            print(f'\033[31m\033[1m[-] Error\033[0m: entity to encrypt must be an existing input_file')
            sys.exit(1)
        else:  
            success = False

        # Run encrypt&hide schema.
        try:
            vault_instance.do_zip()
            vault_instance.do_encryption()
            vault_instance.mask()
            os.rename(f'{args.input_file}.bin', f'{args.input_file}')
            success = True

        # Revert change in case of an error.
        except Exception as e:
            print(f'\033[31m\033[1m[-] Error\033[0m: {e}')
            print('[-] Reverting changes')

            if f'{vault_instance.input_file}.bin' in os.listdir():
                vault_instance.revert_encryption()
                vault_instance.revert_zip()
            elif f'{vault_instance.input_file}.zip' in os.listdir():
                vault_instance.revert_zip()

        # Exit status.
        finally:
            if success:
                print(f'\033[32m\033[1m[+] Success\033[0m')
                sys.exit(0)
            else:
                print(f'\033[31m\033[1m[-] Fail\033[0m')
                sys.exit(1)

    # Decryption.
    elif args.instruction == 'decrypt':
        # Check if file exists.
        if not os.path.exists(f'{args.input_file}'):
            print(f'\033[31m\033[1m[-] Error\033[0m: file does not exist.')
            sys.exit(1)
        else:
            success = False

        # Run discover&decrypt schema.
        try:
            os.rename(f'{args.input_file}', f'{args.input_file}.bin')
            vault_instance.mask()
            vault_instance.revert_encryption()
            vault_instance.revert_zip()
            success = True

        # Revert change in case of an error.
        except Exception as e:
            print(f'\033[31m\033[1m[-] Error\033[0m: {e}')
            print('[-] Reverting changes')

            if f'{vault_instance.input_file}.bin' in os.listdir():
                vault_instance.do_hide()
            elif f'{vault_instance.input_file}.zip' in os.listdir():
                vault_instance.do_encryption()
                vault_instance.do_hide()

        # Exit status.
        finally:
            if success:
                print(f'\033[32m\033[1m[+] Success\033[0m')
                sys.exit(0)
            else:
                print(f'\033[31m\033[1m[-] Fail\033[0m')
                sys.exit(1)

    # Check hassum.
    elif args.instruction == 'hash':
        # Check if file exists.
        if not os.path.exists(f'{args.input_file}'):
            print(f'\033[31m\033[1m[-] Error\033[0m: file does not exist.')
            sys.exit(1)
        else:
            hash_sum = vault_instance.calculate_file_hash(f'{args.input_file}')
            print(f'\033[32m\033[1m[+] Result\033[0m: {hash_sum}')
            sys.exit(0)
