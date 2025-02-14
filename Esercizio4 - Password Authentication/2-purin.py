# PBE
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file, check_len
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass

SALT_LEN = 16
KEY_LEN = 16
NONCE_LEN = 15
TAG_LEN = 16
MIN_CT_LEN = SALT_LEN + NONCE_LEN+ TAG_LEN
NONCE_OFFSET = SALT_LEN+NONCE_LEN
TAG_OFFSET = NONCE_OFFSET+TAG_LEN

class InsecurePasswordError(Exception):
    '''
    Error inserting an insecure password.
    '''

def find_in_password(psw: str, comparisonString:str, isNumbers: bool):
    for char in psw:
        if char in comparisonString:
            return
    if isNumbers:
        msg = "Password needs at least one number"
        raise InsecurePasswordError(msg)
    msg = "Password needs at least one special character (!$%?.&£)"
    raise InsecurePasswordError(msg)

def check_password(psw: str):
    SPECIAL_CHARACTERS = '!$%?.&£'
    NUMBERS = '1234567890'
    if(len(psw) < 8):
        msg = "Password needs to be at least 8 characters long"
        raise InsecurePasswordError(msg)
    find_in_password(psw=psw, comparisonString=SPECIAL_CHARACTERS, isNumbers=False)
    find_in_password(psw=psw, comparisonString=NUMBERS, isNumbers=True)    

def insert_password() -> str:
    prompt = 'Please insert the password:\n'
    while True:
        try:
            psw = input(prompt)
            #check_password(psw)
            return psw
        except(InsecurePasswordError) as err:
            print(err)
    

def get_key(psw: str, salt: str) -> bytes:
    print('Generating key...')
    return scrypt(password=psw, salt=salt, key_len=KEY_LEN, N=2**20, r=8, p=1)

def encrypt():
    psw = insert_password()
    salt = get_random_bytes(SALT_LEN)
    key = get_key(salt=salt, psw=psw)

    pt, _ = read_file(
         subject = 'plaintext',
         error = 'User aborted reading the plaintext',
         default = 'plaintext.txt',
         process = lambda raw: raw
    )
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(pt)

    ct = salt+nonce+tag+ciphertext

    _ = write_file(
        data = ct,
        subject = 'ciphertext',
        error = 'User aborted writing the output',
        default = 'ciphertext.txt'
    )

def decrypt():
    # read ciphertext from file
    ct, _ = read_file(
        subject = 'ciphertext',
        error = 'User aborted reading the ciphertext',
        default = 'ciphertext.txt',
        process = lambda raw: check_len(data=raw, min_len=MIN_CT_LEN)
    )
    
    # ct = salt+nonce+tag+ciphertext
    psw = insert_password()
    key = get_key(psw=psw, salt=salt)
    salt = ct[:SALT_LEN]
    nonce = ct[SALT_LEN:NONCE_OFFSET]
    tag = ct[NONCE_OFFSET:TAG_OFFSET]
    ciphertext = ct[TAG_OFFSET:]

    cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_OCB)
    decipheredText = cipher.decrypt_and_verify(ciphertext, tag)

    _ = write_file(
        data = decipheredText,
        subject = 'decrypted text',
        error = 'User aborted writing the output',
        default = 'decipheredText.txt'
    )

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