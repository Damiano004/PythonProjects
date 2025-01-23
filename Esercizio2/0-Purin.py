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
     #Retrive ascii code of the letters
     ascii_a = ord(letter_a)
     ascii_b = ord(letter_b)
     #Initialize an offset used to remember if the letter is capital or not
     offset = 0
     #Retrive the correct number of the letter
     ascii_a, offset = getLetterNumber(ascii_a)
     ascii_b, _ = getLetterNumber(ascii_b)
     #Summs the two letters to encrypt letter_a
     ascii_a = (ascii_a + ascii_b * multiplier) % 26
     #Adds the offset to ascii_a to make it capital or lower
     ascii_a += offset
     #Returns the retulting letter
     return chr(ascii_a)

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
    # initialize output
    multiplier = -1
    if(mode):
         multiplier = 1
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
        out_str += sumLetter(char, key[i], multiplier)
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
    # check lengths
    if len(key) < len(pt):
        err_str = 'Error: the key is smaller than the plain text'
        raise KeyImportError(err_str)
    # check that the key only contains letters
    for char in key:
        if not isCharacter(char):
            err_str = 'Error: should only contain alphabetical letters'
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