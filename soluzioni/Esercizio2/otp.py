# -- ONE TIME PAD CIPHER--
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file


# normal reference alphabet
ALPH = 'abcdefghijklmnopqrstuvwxyz '

def otp(in_str: str, key: str, encrypting: bool) -> str:
    '''
    Function that performs the core one-time-pad operation.
    Assumes that the input string is at most as long as the key
    and that both strings contain only valid characters
    (defined in ALPH).
    
    ### Parameters
    - in_str: is the string to be (en/de)crypted
    - key: is the string to be used as OTP key
    - encrypting: boolean value that determines whether
        to encrypt (True) or decrypt (False)
    
    ### Returns
    A string of characters that is the (en/de)cryption
    of in_str with key.
    '''
    # initialize output
    out_str = ''
    # cycle on the length of in_str that is assumed to be shorter than key
    for i in range(len(in_str)):
        # find chars position in alphabet
        # they are always positive because strings are assumed to contain
        # only valid characters 
        in_v = ALPH.find(in_str[i])
        key_v = ALPH.find(key[i])
        if encrypting:
            # encrypt
            out_str += ALPH[(in_v + key_v) % len(ALPH)]
        else:
            # decrypt
            out_str += ALPH[(in_v - key_v) % len(ALPH)]
    # return final string
    return out_str

def import_valid_text(raw_data: bytes) -> str:
    '''
    Function that converts a byte string into
    an utf-8 string without trailing newlines,
    and checks that only valid characters are present
    (defined in ALPH).
    
    ### Parameters
    - raw_data: byte string to convert
    
    ### Returns
    The converted string.
    
    ---
    ## Raises
    ReadProcessingError if raw_data cannot be converted to a string
    or there are invalid characters.
    '''
    try:
         # convert bytes to string
         imp_str = raw_data.decode('utf-8').strip('\n')
    except UnicodeDecodeError:
         err_msg = 'Error: the file does not contain a valid string'
         raise ReadProcessingError(err_msg)
    # now check all characters
    err_msg = 'Error: the file contains an invalid character: '
    for char in imp_str:
        # valid characters are contained in ALPH
        if ALPH.find(char) < 0:
             err_msg += f'"{char}"'
             raise ReadProcessingError(err_msg)
    # all good, return string
    return imp_str

def import_message(raw_data: bytes, key_len: int) -> str:
    '''
    Function that imports a message (plaintext or ciphertext).
    Imports the bytes as a valid text and checks that it is not
    longer than the key.
    If maximum length is exceeded it asks the user whether to truncate.
    
    ### Parameters
    - raw_data: byte string of the message to be imported
    - key_len: length of the key, i.e. the maximum length
         allowed for the message
    
    ### Returns
    A valid text of length at most key_len.
    
    ---
    ## Raises
    ReadProcessingError if raw_data is not a valid text or if its length
    is greater than key_len and the user did not want to truncate.
    '''
    # this could raise an exception: desired behaviour
    imp_str = import_valid_text(raw_data)
    imp_len = len(imp_str)
    if imp_len > key_len:
         # excessive length, ask user
         prompt = f'The length of the message ({imp_len}) is greater than'
         prompt += f' the the key ({key_len}), do you want to truncate?'
         prompt += '\n(y to truncate, anything else to cancel)\n'
         choice = input(prompt)
         if choice.lower() == 'y':
             # truncate
             return imp_str[:key_len]
         else:
            raise ReadProcessingError('input too long')
    return imp_str

def en_de_crypt(encrypting: bool):
    '''
    Function that performs the encryption or the decryption,
    reading key and plaintext from file
    and writing the results on file.

    ### Parameters
    - encrypting: boolean value that determines whether
        to encrypt (True) or decrypt (False)
    
    ---
    ## Raises
    LibCryptoError if operations are aborted or plaintext cannot be encrypted.
    '''
    # read key from file
    key, _ = read_file(
         subject = 'key',
         error = 'User aborted reading the key',
         default = 'key.txt',
         process = import_valid_text
    )
    # adjust names
    in_name = 'ciphertext'
    out_name = 'decrypted_text'
    if encrypting:
        in_name = 'plaintext'
        out_name = 'ciphertext'
    # read message
    message, _ = read_file(
         subject = in_name,
         error = f'User aborted reading the {in_name}',
         default = f'{in_name}.txt',
         process = lambda raw: import_message(raw, len(key))
    )
    # (en/de)crypt
    output = otp(message, key, encrypting)
    # write output on file
    out_filename = write_file(
         data = output.encode('utf-8'),
         subject = out_name,
         error = 'User aborted writing the output',
         default = f'{out_name}.txt'
    )
    print(f'Written on {out_filename}')

# main

# define prompt
prompt = '''What do you want to do?
    1 -> encrypt
    2 -> decrypt
    0 -> quit
 -> '''
while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    choice = input(prompt)
    try:
        if choice == '1':
                en_de_crypt(encrypting=True)
        elif choice == '2':
                en_de_crypt(encrypting=False)
        elif choice == '0':
                exit()
        else:
            # default error message for wrong inputs
            print('Invalid choice, please try again!')
    except LibCryptoError as e:
            print(e)