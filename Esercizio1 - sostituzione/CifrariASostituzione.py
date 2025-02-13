class CharacterException (Exception):
    '''This is a custom exception called when the input contains numbers, special characters
    or in general not a letter from the alphabet'''

alphabet = 'abcdefghijklmnopqrstuvwxyz'
#alphabet with random letters
encrypted_alphabet = 'qwertyiopasdfghjklzxcvbnm'

def get_encrypted_letter(letter: str) -> str:
    '''Returns the encrypted version of the letter given in the parameters according to the
    encrypted alphabet'''
    if(letter == ' '):
        return ' '
    #search for the letter in the normal alphabet
    index = alphabet.find(letter)
    if(index!=-1):
        #return the letter in the encrypted alphabet that matches the position of the letter
        return encrypted_alphabet[index]
    raise CharacterException("Please just inster letters from a to z")

def encrypt_message(message: str) ->str:
    '''Encrypts the whole message given in the input field of the function and returns it'''
    output = ""
    message = message.lower()
    #cycles through each letter of the message
    for letter in message:
        #encrypts the message
        encrypted_letter = get_encrypted_letter(letter)
        output+= encrypted_letter
    return output

while True:
    user_input = input("Enther a message and I'll encrypt that for you:\n")
    try:
        final_message = encrypt_message(user_input)
    except CharacterException as exeption:
        print(exeption)
    else:
        print (f'The encrypted message according by this alphabet: {encrypted_alphabet} is the following:\n{final_message}')
        break