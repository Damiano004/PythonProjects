# --SUBSTITUTION CIPHER--
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file

def isCharacter(in_char: str) -> bool:
     '''
     Function that returns whether an input string
     is an alphabetical letter or not

     ### Parameters
     - in_char: is the character that the function will check

     ### Returns
     A boolean value where:
     - True -> the input is an alphabetical letter
     - False -> the input is not an alphabetical letter
     '''
     in_char = in_char.lower()
     if ord(in_char)<97 | ord(in_char)>122:
          return False
     return True
     
def sumLetter(letter_a: str, letter_b:str) -> str:
     '''
     Function that adds the two letters and returns the
     resulting letter, (letter_a + letter_b)

     ### Parameters
     - letter_a: the letter that gets summed by letter_b
     - letter_b: the letter that summs letter_a

     ### Returns
     A letter that is the result between the sum of letter_a and letter_b
     '''
     ascii_a = ord(letter_a)
     ascii_b = ord(letter_b)
     offset = 0
     if ascii_a-65 <=25:
          offset = 65
     else:
        offset = 97
     if ascii_b-65 <=25:
          ascii_b -= 65
     else:
        ascii_b -= 97
     ascii_a -= offset
     ascii_a = (ascii_a + ascii_b) % 26
     ascii_a += offset
     return chr(ascii_a)
               
          


def substitute(in_str: str, key: str) -> str:
    '''
    Function that performs the core substitution operation.
    
    ### Parameters
    - in_str: is the string whose characters will be substituted
    - key: is the key that will be used to encrypt the plain text
    
    ### Returns
    A string containint the encrypted message.

    ---
    ## Raises
    LibCryptoError if in_str contains characters
    that are not alphabetical characters.
    '''
    # initialize output
    out_str = ''
    i = 0
    # substitute every character
    for char in in_str:
        # find position in reference alphabet
        if not isCharacter(char):
            # character not found, raise error
            err_str = f'Error: message contains an invalid character: "{char}"'
            raise LibCryptoError(err_str)
        # append to output the corresponding character in the permuted alphabet
        out_str += sumLetter(char, key[i])
        i += 1
    # return final string
    return out_str

def check_key(key: str, pt:str) -> None:
    '''
    Function that checks the validity of a key, i.e. if it has the
    same length as the plain text.
    
    ### Parameters
    - key: string representing the key used for encrypt the message
    - pt: string representing the plain text
    
    ### Returns
    Nothing if the key is valid.

    ---
    ## Raises
    KeyImportError if key has not the same length as the pt.
    '''
    # initialize error string, will be completed
    err_str = 'Error: key and plain text '
    # check lengths
    if len(key) != len(pt):
        err_str += 'do not have the same length'
        raise KeyImportError(err_str)
    # check that every character of ALPH is present in key
    err_str = 'Error: should only contain alphabetical letters'
    for char in key:
        if isCharacter(char):
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
    return key

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
    # read message
    pt, _ = read_file(
         subject = 'plaintext',
         error = 'User aborted reading the plaintext',
         default = 'plaintext.txt',
         process = lambda raw: import_trimmed_string(raw)
    )
    # check validity
    #check_key(key)
    print('The plaintext is:\n', pt)
    # encrypt
    ct = substitute(pt, key)
    # write ciphertext on file
    out_filename = write_file(
         data = ct.encode('utf-8'),
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
    pt = substitute(ct, key)
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

