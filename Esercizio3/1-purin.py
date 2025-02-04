# --SIMMETRIC CIPHER--
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
import base64

CHACHA20_NONCE_LENGTH = 12

def stirng_to_base64(string: bytes) -> bytes:
    '''
    Function that converts an utf-8 string into
    a base64 type of bytes.
    
    ### Parameters
    - string: the string to convert
    
    ### Returns
    The converted raw data.
    
    ---
    ## Raises
    ReadProcessingError if the input type isn't either a byte or a string.
    '''
    try:
         return base64.b64decode(string)
    except TypeError:
         err_msg = 'Error: input should be string or byte'
         raise ReadProcessingError(err_msg)

def byte_to_base64(raw_data: bytes) -> bytes:
    '''
    Function that converts a byte string into
    a base64 type of bytes.
    
    ### Parameters
    - raw_data: byte string to convert
    
    ### Returns
    The string converted in base64.
    
    ---
    ## Raises
    ReadProcessingError if the input type isn't either a byte or a string.
    '''
    try:
         return base64.b64encode(raw_data)
    except TypeError:
         err_msg = 'Error: input should be string or byte'
         raise ReadProcessingError(err_msg)

def encrypt():
    '''
    Function that performs the encryption, reding the plaintext from file,
    generating a random key and nonce and writing the result on file.
    '''
    #make the user decide whether to use or not the authentication
    prompt = "Would you like to authenticate the message? (y/n)"
    while True:
        choice = input(prompt)
        match choice.lower():
            case 'y':
                print()
            case 'n':
                #continue normally
                break
            case _:
                # default error message for wrong inputs
                print('Invalid choice, please try again!')
    
    #normal cypher uses ChaCha20
    #generate a random key and nonce
    key = get_random_bytes(32)
    nonce = get_random_bytes(CHACHA20_NONCE_LENGTH)

    #ask the user for a plain text
    pt, _ = read_file(
         subject = 'plaintext',
         error = 'User aborted reading the plaintext',
         default = 'plaintext.txt',
         process = lambda raw: raw
    )
    
    #encryption
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ct = cipher.encrypt(pt)

    #saving the ct and key on files
    key_file = write_file(
         data = byte_to_base64(key),
         subject = 'key value',
         error = 'User aborted writing the output',
         default = f'key.txt'
    )
    _ = write_file(
         data = byte_to_base64(nonce),
         subject = 'nonce value',
         error = 'User aborted writing the output',
         default = f'nonce.txt'
    )
    out_filename = write_file(
         data = byte_to_base64(ct),
         subject = 'decrypted text',
         error = 'User aborted writing the output',
         default = f'ciphertext.txt'
    )
    print(f'Written files:\nCT: {out_filename}\nKey: {key_file}\n')

def decrypt():
    '''
    Function that performs the decryption, reading key and ciphertext
    from file and writing the retunt on file.
    '''
    # read key from file
    key, _ = read_file(
         subject = 'key',
         error = 'User aborted reading the key',
         default = 'key.txt',
         process = lambda raw: stirng_to_base64(raw)
    )
    # read ciphertext from file
    ct, _ = read_file(
         subject = 'ciphertext',
         error = 'User aborted reading the ciphertext',
         default = 'ciphertext.txt',
         process = lambda raw: stirng_to_base64(raw)
    )

    nonce, _ = read_file(
         subject = 'nonce',
         error = 'User aborted reading the ciphertext',
         default = 'nonce.txt',
         process = lambda raw: stirng_to_base64(raw)
    )
    #extract the noncr from the ciphertext
    print(f'lunghezza di nonce: {len(nonce)}')
    cipher = ChaCha20.new(key=key, nonce=nonce)
    pt = cipher.decrypt(ct)
    pt_file = write_file(
         data = byte_to_base64(pt),
         subject = 'decrypted text',
         error = 'User aborted writing the output',
         default = f'decriptedtext.txt'
    )
    print(f'Written files:\nCT: {pt_file}')


# <----------------------- main ----------------------->
prompt = '''What do you want to do?
    1 -> encrypt
    2 -> decrypt
    0 -> quit
 -> '''

while True:
    # get user's choice and call appropriate function
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
        