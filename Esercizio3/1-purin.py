# --SIMMETRIC CIPHER--
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
import base64

# Setting ciphers constants
AES_TAG_LENGTH = 16
AES_NONCE_LENGTH = 11
CHACHA20_NONCE_LENGTH = 12

def base64_to_byte(b64_input: bytes) -> bytes:
    '''
    Function that converts base64 encoded data into its raw byte form.
    
    ### Parameters
    - b64_input: the base64 data to convert
    
    ### Returns
    The decoded raw data as bytes.
    
    ---
    ## Raises
    ReadProcessingError if the input type isn't either a byte or a string.
    '''
    try:
         return base64.b64decode(b64_input)
    except TypeError:
         err_msg = 'Error: input should be string or byte'
         raise ReadProcessingError(err_msg)

def byte_to_base64(raw_data: bytes) -> bytes:
    '''
    Function that converts raw byte data into its base64 form.
    
    ### Parameters
    - raw_data: raw data that will be converted
    
    ### Returns
    The data converted in base64 in bytes.
    
    ---
    ## Raises
    ReadProcessingError if the input type isn't either a byte or a string.
    '''
    try:
         return base64.b64encode(raw_data)
    except TypeError:
         err_msg = 'Error: input should be string or byte'
         raise ReadProcessingError(err_msg)

def encrypt_normal(input_text: str)-> tuple[str,str]:
    '''
    Function that performs the encryption without the authntication using ChaCha20.

    ### Parameters
    - input_text: a string that contains the plaintext

    ### Returns
    Two string:
    - the first is the ciphertext (containing nonce+ct)
    - the second is the key
    '''
    #normal cypher uses ChaCha20
    #generate a random key and nonce
    key = get_random_bytes(32)
    nonce = get_random_bytes(CHACHA20_NONCE_LENGTH)
    
    #initialize the ChaCha20 cifer
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ct = cipher.encrypt(input_text)
    ct = nonce+ct
    return ct, key

def encrypt_autentication(input_text: str)-> tuple[str,str]:
    '''
    Function that performs the encryption without the authntication using AES in CCM mode.

    ### Parameters
    - input_text: a string that contains the plaintext

    ### Returns
    Two string:
    - the first is the ciphertext (containing nonce+ct)
    - the second is the key
    '''
    #cipher with authentication uses AES with CCM mode
    #generate a random key and nonce
    key = get_random_bytes(16)
    nonce = get_random_bytes(AES_NONCE_LENGTH)
    #initialize the AES_CCM cifer
    cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_CCM)
    #encrypting
    ct, tag = cipher.encrypt_and_digest(input_text)
    ct = nonce+tag+ct
    return ct,key

def encrypt():
    '''
    Function that performs the encryption, reding the plaintext from file,
    generating a random key and nonce and writing the result on file.

    ---
    ## Raises
    A LibCryptoError if it isn't capable of finding the key value or the ciphertext
    value due to a complication in the encryption
    '''
    #ask the user for a plain text
    pt, _ = read_file(
         subject = 'plaintext',
         error = 'User aborted reading the plaintext',
         default = 'text\plaintext.txt.txt',
         process = lambda raw: raw
    )

    #make the user decide whether to use or not the authentication
    prompt = "Would you like to authenticate the message? (y/n)"
    while True:
        choice = input(prompt)
        match choice.lower():
            case 'y':
                ct, key = encrypt_autentication(pt)
                break
            case 'n':
                ct, key = encrypt_normal(pt)
                break
            case _:
                # default error message for wrong inputs
                print('Invalid choice, please try again!')

    #saving the ct and key on files
    try:
        key_file = write_file(
            data = byte_to_base64(key),
            subject = 'key value',
            error = 'User aborted writing the output',
            default = 'key.txt'
        )

        out_filename = write_file(
            data = byte_to_base64(ct),
            subject = 'decrypted text',
            error = 'User aborted writing the output',
            default = 'ciphertext.txt'
        )
        print(f'Written files:\nCT: {out_filename}\nKey: {key_file}\n')
    except NameError:
        error = "Error: ciphertext or key is empty, something went wrong " 
        error+= "douring the encryption"
        raise LibCryptoError(error)

def decrypt_normal(key:str, ct:str) -> str:
    '''
    Function that performs the normal decryption using ChaCha20

    ### Parameters
    - key: a string containing the key
    - ct: a string containing the ciphertext

    ### Returns
    The decipphered text using the ChaCha20 cipher

    ---
    ## Raises
    A LibCriptoError if something goes wrong douring the decryption or if the
    nonce has a different length than the pre-enstablished one
    '''
    #extract the nonce from the ciphertext
    try:
        nonce = ct[:CHACHA20_NONCE_LENGTH]
        cifertext = ct[CHACHA20_NONCE_LENGTH:]
    except IndexError:
        error = "Error: something whent wrond douring ChaCha20 decryption, "
        error+= "the index went out of range!"
        raise LibCryptoError(error)
    
    try:
        #initialize the ChaCha20 cifer
        cipher = ChaCha20.new(key=key, nonce=nonce)
        #return the deciphered text
        return cipher.decrypt(cifertext)
    except (ValueError,KeyError):
        error = "Error: douring the normal decryption\n"
        error += "Make sure to use the same method for both encryption and decryption"
        raise LibCryptoError(error)

def decrypt_autentication(key: str, ct: str) -> str:
    '''
    Function that performs an authenticated decryption using AES_CCM

    ### Parameters
    - key: a string containing the key
    - ct: a string containing the ciphertext

    ### Returns
    The decipphered text using the AES_CCM mode cipher

    ---
    ## Raises
    A LibCriptoError if something goes wrong douring the decryption or if the
    nonce and/or tag have a different length than the pre-enstablished one
    '''
    #extract the nonce and tag from the cifertext
    try:
        #indicates the index where the tag ends in the ct string
        tagEnd = AES_NONCE_LENGTH+AES_TAG_LENGTH

        nonce = ct[:AES_NONCE_LENGTH]
        tag = ct[AES_NONCE_LENGTH:tagEnd]
        ciphertext = ct[tagEnd:]
    except IndexError:
        error = "Error: something whent wrond douring AES_CCM decryption, "
        error+= "the index went out of range!"
        raise LibCryptoError(error)
    
    try:
        #initialize the AES cipher
        cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_CCM)
        #return the deciphered text
        return cipher.decrypt_and_verify(ciphertext,tag)
    except (ValueError, KeyError):
        error = "Error: douring the authenticated decryption\n"
        error += "Make sure to use the same method for both encryption and decryption"
        raise LibCryptoError(error)

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
         process = lambda raw: base64_to_byte(raw)
    )
    # read ciphertext from file
    ct, _ = read_file(
         subject = 'ciphertext',
         error = 'User aborted reading the ciphertext',
         default = 'ciphertext.txt',
         process = lambda raw: base64_to_byte(raw)
    )

    prompt = "Would you like to authenticate the message? (y/n)"
    while True:
        choice = input(prompt)
        match choice.lower():
            case 'y':
                pt = decrypt_autentication(key=key,ct=ct)
                break
            case 'n':
                pt = decrypt_normal(key=key,ct=ct)
                break
            case _:
                # default error message for wrong inputs
                print('Invalid choice, please try again!')
    
    #export the decrypted message
    pt_file = write_file(
         data = pt,
         subject = 'decrypted text',
         error = 'User aborted writing the output',
         default = 'decipheredText.txt'
    )
    print(f'Written files:\nCT: {pt_file}')


# <----------------------- main -----------------------> #
prompt = '''What do you want to do?
    1 -> encrypt
    2 -> decrypt
    0 -> quit
 -> '''

while True:
    try:
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
    except (LibCryptoError, ReadProcessingError) as err:
        print(err)