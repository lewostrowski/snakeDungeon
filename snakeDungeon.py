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
from stegano import lsb

class Vault:
    """
    Handle zip encryption/decryption.

    Attributes:
        folder_name (string): Name of a folder to zip/unzip.
    """
    
    def __init__(self, folder_name, cover, password, salt):
        """
        Initialize instance.

        Args:
            folder_name (string): Name of a folder to zip/unzip.
            cover (string): Path to a file with hidden information.
            password (string): User provided password.
            salt (string): User provided salt.
        """
        self.folder_name = folder_name
        self.cover = cover
        self.password = password
        self.salt = salt
        
    def password_processor(self):
        """ Transform given password into 32 bytes length key encoded by base64."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            iterations=100000
        )
        
        key = kdf.derive(self.password.encode())
        return base64.urlsafe_b64encode(key)
    
    
    def do_zip(self):
        """Zip folder and remove it."""
        with zipfile.ZipFile(f'{self.folder_name}.zip', 'w') as zip_me:
            for root, _, files  in os.walk(self.folder_name):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_me.write(file_path)
                    
        shutil.rmtree(self.folder_name)
        print(f'[+] \033[1m{self.folder_name}\033[0m zipped')    
    
    def do_encryption(self):
        """Encrypt zipped folder and remove zip file."""
        with open(f'{self.folder_name}.bin', 'wb') as encrypted_file:
            # Read zip content.
            with open(f'{self.folder_name}.zip', 'rb') as zip_file:
                zip_content = zip_file.read()
    
            # Encrypt zip content.
            cipher = Fernet(self.password_processor())
            encrypted_zip = cipher.encrypt(zip_content)
            encrypted_file.write(encrypted_zip)
            
        os.remove(f'{self.folder_name}.zip')
        print(f'[+] \033[1m{self.folder_name}\033[0m encrypted')    
    
    def do_hide(self):
        """Hide encrypted file behind image and delete it."""
        with open(f'{self.folder_name}.bin', 'rb') as encrypted_file:
            binary_data = encrypted_file.read()
            encoded_data = base64.b64encode(binary_data).decode()
    
        steg_img = lsb.hide(self.cover, encoded_data)
        steg_img.save(self.cover)
    
        os.remove(f'{self.folder_name}.bin')
        print(f'[+] \033[1m{self.folder_name}\033[0m hidden in \033[1m{self.cover}\033[0m')    
    
    def revert_zip(self):
        """Unzip archive and delete it."""
        with zipfile.ZipFile(f'{self.folder_name}.zip', 'r') as revert_zipping:
            revert_zipping.extractall()
            
        os.remove(f'{self.folder_name}.zip')
        print(f'[+] \033[1m{self.folder_name}\033[0m unzipped')    
    
    def revert_encryption(self):
        """Decrypt binary file and delete it."""
        # Read encrypted file
        with open(f'{self.folder_name}.bin', 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
            cipher = Fernet(self.password_processor())
            decrypted_data = cipher.decrypt(encrypted_data)
    
        os.remove(f'{self.folder_name}.bin')
        
        # Decrypt and save as zip
        with open(f'{self.folder_name}.zip', 'wb') as zip_me:
            zip_me.write(decrypted_data)

        print(f'[+] \033[1m{self.folder_name}\033[0m decrypted')    
    
    def revert_hide(self):
        """Discover hidden binary."""
        extracted_data = lsb.reveal(self.cover)
        decoded_data = base64.b64decode(extracted_data.encode())
    
        with open(f'{self.folder_name}.bin', "wb") as encrypted_file:
            encrypted_file.write(decoded_data)

        print(f'[+] \033[1m{self.folder_name}\033[0m dicovered')    


if __name__ == '__main__':
    # Parse arguments.
    parser = argparse.ArgumentParser(
                        prog='snakeDungeon - DIY encryption tool',
                        description='Python script for encryption and steganography automation.',
                        epilog='v1')
    
    parser.add_argument('instruction', help='Choose whether to 1) encrypt or 2) decrypt.')
    parser.add_argument('folder', help='Folder path to 1) encrypt, 2) hold decrypted files.')
    parser.add_argument('cover', help='Image path 1) with encrypted data, 2) to write encrypted data.')
    args = parser.parse_args()
    
    # Get password & salt.
    password = getpass.getpass(f'[+] Encrypt \033[1m{args.folder}\033[0m with password: ')
    salt = getpass.getpass(f'[+] Salt for \033[1m{args.folder}\033[0m: ')

    # Init job.
    vault_instance = Vault(args.folder, args.cover, password, salt)

    # Encryption.    
    if args.instruction == 'encrypt':
        #Check if target and cover image exists & ask to repeat password.
        if not os.path.isdir(args.folder) or not os.path.exists(args.folder) or not os.path.exists(args.cover):
            print(f'\033[31m\033[1m[-] Error\033[0m: entity to encrypt must be an existing folder')
            sys.exit(1)
        else:
            repeat = getpass.getpass('[+] Repeat password: ')
            if password != repeat:
                print(f'\033[31m\033[1m[-] Error\033[0m: passwords does not match')
                sys.exit(1)
                        
            success = False

        # Run encrypt&hide schema.
        try:
            vault_instance.do_zip()
            vault_instance.do_encryption()
            vault_instance.do_hide()
            success = True

        # Revert change in case of an error.
        except Exception as e:
            print(f'\033[31m\033[1m[-] Error\033[0m: {e}')
            print('[-] Reverting changes')

            if f'{vault_instance.folder_name}.bin' in os.listdir():
                vault_instance.revert_encryption()
                vault_instance.revert_zip()
            elif f'{vault_instance.folder_name}.zip' in os.listdir():
                vault_instance.revert_zip()
            else:
                vault_instance.revert_hide()
                vault_instance.revert_encryption()
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
        # Check if cover image exists.
        if not os.path.exists(args.cover):
            print(f'\033[31m\033[1m[-] Error\033[0m: cover image does not exist')
            sys.exit(1)
        else:
            success = False

        # Run discover&decrypt schema.
        try:
            vault_instance.revert_hide()
            vault_instance.revert_encryption()
            vault_instance.revert_zip()
            success = True

        # Revert change in case of an error.
        except Exception as e:
            print(f'\033[31m\033[1m[-] Error\033[0m: {e}')
            print('[-] Reverting changes')

            if f'{vault_instance.folder_name}.bin' in os.listdir():
                vault_instance.do_hide()
            elif f'{vault_instance.folder_name}.zip' in os.listdir():
                vault_instance.do_encryption()
                vault_instance.do_hide()
            else:
                vault_instance.do_zip()
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
