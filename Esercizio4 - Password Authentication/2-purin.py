# PBE
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file, check_len
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass

# ====== INITIALIZE CONSTANTS ===================
SALT_LEN = 16
KEY_LEN = 16
NONCE_LEN = 15
TAG_LEN = 16
MIN_CT_LEN = SALT_LEN + NONCE_LEN+ TAG_LEN
NONCE_OFFSET = SALT_LEN+NONCE_LEN
TAG_OFFSET = NONCE_OFFSET+TAG_LEN
# ===============================================

class InsecurePasswordError(Exception):
    '''
    Error due to a weak password.
    '''

def check_password(psw: str):
    '''
    This function checks the password by verifying if its length is at least 8
    and if it has at least one number and special character.

    ### Parameters
    - psw: The password to be checked.

    ---
    ## Raises
    An InsecurePasswordError if the password requirements are not met
    '''
    # Initialize special characters and numbers
    DEFAULT_PSWS = ['password','12345678','qwertyui']

    if len(psw) < 8:
        msg = "Password needs to be at least 8 characters long"
        raise InsecurePasswordError(msg)
    if psw in DEFAULT_PSWS:
        msg = "Password can't be one of the default passwords (password, 12345678"
        msg += ", qwertyui...)"
        raise InsecurePasswordError(msg)

def insert_password() -> str:
    '''
    Manages password input.
    Checks its strength with the function check_password().

    ### Returns
    The secure password
    '''
    prompt = 'Please insert the password:\n'
    while True:
        try:
            psw = getpass(prompt=prompt, stream='*')
            check_password(psw)
            return psw
        except InsecurePasswordError as err:
            print(err)

def get_key(psw: str, salt: str) -> bytes:
    '''
    Retrieves the key from the password and salt.

    ### Parameters:
    - psw: the password input
    - salt: the salt needed to generate the key

    ### Returns
    The key as a byte value
    '''
    # It takes a few seconds, so I print a message to check if it's doing something.
    print('Generating key...')
    return scrypt(password=psw, salt=salt, key_len=KEY_LEN, N=2**20, r=8, p=1)

def encrypt():
    '''
    Encrypts the message using the AES-OCB cipher.
    '''
    # getting the password
    psw = insert_password()
    # retrieving key
    salt = get_random_bytes(SALT_LEN)
    key = get_key(salt=salt, psw=psw)
    # asking for the plaintext to the user
    pt, _ = read_file(
         subject = 'plaintext',
         error = 'User aborted reading the plaintext',
         default = 'plaintext.txt',
         process = lambda raw: raw
    )
    # initializing the nonce
    nonce = get_random_bytes(NONCE_LEN)
    # initializing the AES cipher
    cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_OCB)
    # encrypting the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(pt)
    # assembles the ciphertext message
    ct = salt+nonce+tag+ciphertext
    # writing the message on bin file
    _ = write_file(
        data = ct,
        subject = 'ciphertext',
        error = 'User aborted writing the output',
        default = 'ciphertext.bin'
    )

def decrypt():
    '''
    Decrypts an encrypted message using AES-OCB mode.
    '''
    # read ciphertext from file
    ct, _ = read_file(
        subject = 'ciphertext',
        error = 'User aborted reading the ciphertext',
        default = 'ciphertext.bin',
        process = lambda raw: check_len(data=raw, min_len=MIN_CT_LEN)
    )
    # ct = salt+nonce+tag+ciphertext
    # getting password
    psw = insert_password()
    salt = ct[:SALT_LEN]
    # retrieving the key
    key = get_key(psw=psw, salt=salt)
    # separating the nonce and the tag from the ciphertext
    nonce = ct[SALT_LEN:NONCE_OFFSET]
    tag = ct[NONCE_OFFSET:TAG_OFFSET]
    ciphertext = ct[TAG_OFFSET:]
    # initializing the cipher
    cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_OCB)
    try:
        # decrypting message
        decipheredText = cipher.decrypt_and_verify(ciphertext, tag)
    except (KeyError, ValueError) as err:
        # catching eventual errors
        msg = "An error occurred during the decryption. This could be due to an "
        msg += "incorrect password or the file has been corrupted.\n"
        msg += str(err)
        raise LibCryptoError(msg)
    # writing the decrypted text to file 
    _ = write_file(
        data = decipheredText,
        subject = 'decrypted text',
        error = 'User aborted writing the output',
        default = 'decipheredText.txt'
    )

# <----------------------- Main -----------------------> #
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
    except LibCryptoError as err:
        print(err)