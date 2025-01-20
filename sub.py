# --SUBSTITUTION CIPHER--
from soluzioni.crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from soluzioni.crypto_utils import read_file, write_file


# normal reference alphabet
ALPH = 'abcdefghijklmnopqrstuvwxyz '

def substitute(in_str: str, ref_alph: str, perm_alph: str) -> str:
    '''
    Function that performs the core substitution operation.
    Can be inverted by simply swapping the input alphabets.
    Assumes that the two alphabets contain the same characters,
    with no repetitions.
    
    ### Parameters
    - in_str: is the string whose characters will be substituted
    - ref_alph: is the reference alphabet
    - perm_alph: is the permuted alphabet
    
    ### Returns
    A string whose characters are the ones of in_str substituted
    according to the alphabets.

    ---
    ## Raises
    LibCryptoError if in_str contains characters
    not present in the alphabets.
    '''
    # initialize output
    out_str = ''
    # substitute every character
    for char in in_str:
        # find position in reference alphabet
        index = ref_alph.find(char)
        if index < 0:
            # character not found, raise error
            err_str = f'Error: message contains an invalid character: "{char}"'
            raise KeyImportError(err_str)
        # append to output the corresponding character in the permuted alphabet
        out_str += perm_alph[index]
    # return final string
    return out_str

def check_key(key: str) -> None:
    '''
    Function that checks the validity of a key, i.e. if it is a
    permutation of the alphabet ALPH.
    
    ### Parameters
    - key: string representing the permuted alphabet to check
    
    ### Returns
    Nothing if the key is valid.

    ---
    ## Raises
    KeyImportError if key is not a permutation of ALPH.
    '''
    # initialize error string, will be completed
    err_str = 'Error: key and alphabet '
    # check lengths
    if len(key) != len(ALPH):
        err_str += 'do not have the same length'
        raise LibCryptoError(err_str)
    # check that every character of ALPH is present in key
    err_str += 'do not contain the same characters'
    for char in ALPH:
        if key.find(char) < 0:
            raise KeyImportError(err_str)


def import_trimmed_string(raw_data: bytes) -> str:
    '''
    Function that converts a byte string into
    an utf-8 string without trailing newlines.
    
    ### Parameters
    - raw_data: byte string to convert
    
    ### Returns
    The converted string.
    
    ---
    ## Raises
    ReadProcessingError if raw_data cannot be converted to a string.
    '''
    try:
         return raw_data.decode('utf-8').strip('\n')
    except UnicodeDecodeError:
         err_msg = 'Error: the file does not contain a valid string'
         raise ReadProcessingError(err_msg)

def import_key(raw_data: bytes) -> str:
    '''
    Function that imports a key (permutation of ALPH).
    
    ### Parameters
    - raw_data: byte string of the key encoding to import
    
    ### Returns
    A valid key (i.e. a string with a permutation of ALPH).
    
    ---
    ## Raises
    ReadProcessingError if raw_data is not the encoding of a valid key.
    '''
    # this could raise an exception: desired behaviour
    key = import_trimmed_string(raw_data)
    try:
         check_key(key)
    except KeyImportError as e:
         raise ReadProcessingError(str(e))

def encrypt():
    '''
    Function that performs the encryption, reading key and plaintext
    from file and writing the results on file.

    ---
    ## Raises
    LibCryptoError if operations are aborted or plaintext cannot be encrypted.
    '''
    
    # read key from file
    key, _ = read_file(
         subject = 'key',
         error = 'User aborted reading the key',
         default = 'key.txt',
         process = lambda raw: import_key(raw)
    )
    # check validity
    check_key(key)
    # read message
    pt, _ = read_file(
         subject = 'plaintext',
         error = 'User aborted reading the plaintext',
         default = 'plaintext.txt',
         process = lambda raw: import_trimmed_string(raw)
    )
    print('The plaintext is:\n', ct)
    # encrypt
    ct = substitute(pt, ALPH, key)
    # write ciphertext on file
    out_filename = write_file(
         data = pt.encode('utf-8'),
         subject = 'decrypted text',
         error = 'User aborted writing the output',
         default = f'ciphertext.txt'
    )
    print(f'Written on {out_filename}')

def decrypt():
    '''
    Function that performs the decryption, reading key and ciphertext
    from file and writing the results on file.

    ---
    ## Raises
    LibCryptoError if operations are aborted or ciphertext cannot be decrypted.
    '''
    # read key from file
    key, _ = read_file(
         subject = 'key',
         error = 'User aborted reading the key',
         default = 'key.txt',
         process = lambda raw: import_key(raw)
    )
    # read ciphertext from file
    ct, ct_filename = read_file(
         subject = 'ciphertext',
         error = 'User aborted reading the ciphertext',
         default = 'ciphertext.txt',
         process = lambda raw: import_trimmed_string(raw)
    )
    print('The ciphertext is:\n', ct)
    # decrypt (inverting alph and key)
    pt = substitute(ct, key, ALPH)
    # write result
    print('The decrypted message is:\n', pt)
    out_filename = write_file(
         data = pt.encode('utf-8'),
         subject = 'decrypted text',
         error = 'User aborted writing the output',
         default = f'{ct_filename}_dec.txt'
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
                encrypt()
        elif choice == '2':
                decrypt()
        elif choice == '0':
                exit()
        else:
            # default error message for wrong inputs
            print('Invalid choice, please try again!')
    except LibCryptoError as e:
            print(e)
