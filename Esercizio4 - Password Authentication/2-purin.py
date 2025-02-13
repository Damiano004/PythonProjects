# PBE
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass

def check_password(psw: str) -> tuple[bool, str]:
    if(psw < 8):
        msg = "Password needs to be at least long 8 character"
        return False, msg
    if()

def insert_password() -> str:
    prompt = 'Please insert the password for the encryption'
    psw = input(prompt)
    
    return ""

def encrypt():
    print('function not yet implemented')

def decrypt():
    print('function not yet implemented')

# <----------------------- main -----------------------> #
prompt = '''What do you want to do?
    1 -> encrypt
    2 -> decrypt
    0 -> quit
 -> '''

while True:
    try:
        # get user's choice and call the appropriate function
        choice = input(prompt)
        match choice:
            case '1':
                encrypt()
            case '2':
                decrypt()
            case '0':
                exit()
            case _:
                # default error message for wrong inputs
                print('Invalid choice, please try again!')
    except (LibCryptoError, ReadProcessingError) as err:
        print(err)