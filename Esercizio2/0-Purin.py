# --SUBSTITUTION CIPHER--
from crypto_utils import LibCryptoError, ReadProcessingError, KeyImportError
from crypto_utils import read_file, write_file
# Variable that contains the  new line components (CRLF)
CRLF = f'{chr(10)}{chr(13)}'
# Variable that contains all the characters that are valid for the encryption
ALPHABET = f"1234567890$%()=+|-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .;:_<>#,!?@'ÉÈÀÒÌÙèàùòìé{CRLF}"

def checkStringValidity(in_string: str) -> None:
     '''
     Function that checks if an input string is in the reference alphabet

     ### Parameters
     - in_string: is the string that the function will check

     ---
     ## Raises
     A KeyImportError if the string contains a character that is not
     in the reference alphabet
     '''
     for char in in_string:
        if ALPHABET.find(char) < 0:
            err_str = f'Character not found in the reference alphabet {char}'
            raise KeyImportError(err_str)

def getLetterNumber(letter:int) -> tuple[int , int]:
     '''
     Funcion that returns the number of the letter in an alphabetical
     order(from 0 to 25 where 0 is a and 25 if z)
     This also returns an offset to indicate whether the letter is capital
     or lower.

     ### Parameters
     - letter: the ascii code of the character whose number will be returned

     ### Returns
     - Integer: the number of the letter [0-25]
     - Offset: an offset that determines if the letter is capital (65) or lower (97)
     '''
     #Check if the letter is capital or lower
     if letter-65 <=25:
          return letter-65, 65
     return letter-97, 97
     
def sumLetter(letter_a: str, letter_b:str, multiplier: int) -> str:
     '''
     Function that adds the two letters and returns the
     resulting letter, (letter_a + letter_b * multiplier)

     ### Parameters
     - letter_a: the letter that gets summed by letter_b
     - letter_b: the letter that summs letter_a
     - multiplier: a number applied to letter_b to enable a dual funcionality

     ### Returns
     A letter that is the result between the sum of letter_a and letter_b
     '''
     # retrive positions in the alphabet
     pos_a = ALPHABET.find(letter_a)
     pos_b = ALPHABET.find(letter_b)
     # sum the positions
     sum = (pos_a + pos_b * multiplier) % len(ALPHABET)
     # return the resulting letter
     return ALPHABET[sum]

def substitute(in_str: str, key: str, mode: bool) -> str:
    '''
    Function that performs the core substitution operation.
    
    ### Parameters
    - in_str: is the string whose characters will be substituted
    - key: is the key that will be used to encrypt the plain text
    - mode: a boolean that dictates if it should encrypt (true) or decrypt (false)
    
    ### Returns
    A string containint the encrypted message.

    ---
    ## Raises
    LibCryptoError if in_str contains characters
    that are not alphabetical characters.
    '''
    # check validity of input string
    checkStringValidity(in_str)
    # initialize multiplier
    multiplier = -1
    if(mode):
         multiplier = 1
    # initialize output string
    out_str = ''
    i = 0
    # substitute every character
    for char in in_str:
        # append to output the corresponding character in the permuted alphabet
        out_str += sumLetter(char, key[i], multiplier)
        i += 1
    # return final string
    return out_str

def check_key(key: str, rt:str) -> None:
    '''
    Function that checks the validity of a key, i.e. if it has the
    same length as the plain text.
    
    ### Parameters
    - key: string representing the key used for encrypt the message
    - rt: string representing the referenced text
    
    ### Returns
    Nothing if the key is valid.

    ---
    ## Raises
    KeyImportError if key has not the same length as the pt.
    '''
    # check key validity
    checkStringValidity(key)
    # check lengths
    if len(key) < len(rt):
        err_str = 'Error: the key is smaller than the referenced text'
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
    # check key validity
    check_key(key, pt)
    print('The plaintext is:\n', pt)
    # encrypt
    ct = substitute(pt, key, True)
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
    # check key validity
    check_key(key, ct)
    print('The ciphertext is:\n', ct)
    # decrypt (inverting alph and key)
    pt = substitute(ct, key, False)
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