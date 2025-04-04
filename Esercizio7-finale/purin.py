from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import BLAKE2b
from Crypto.Cipher import AES
from getpass import getpass
import json
import os.path

def process_pwd(password: str, salt: bytes) -> bytes:
    '''
    Function that uses a KDF to create a secure key

    ### PARAMETERS
    - password: the password inserted by the user
    - salt: the salt used to create the key

    ### RETURNS:
    The key created by the scrypt KDF
    '''
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    return key 

def load_data(path: str, password: str) -> str:
    '''
    Function that decrypts the credentials found in the given path

    ### PARAMETERS:
    - path: the path where the file is located
    - password: the password needed to decrypt the file

    ### RETURNS:
    The credentials found in the file

    ---
    ## RAISES
    IDError if the decrypted data isn't valid
    '''
    # reading file
    with open(path, 'rb') as in_file:
        # retriving the data needed for the dencryption
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
        
    
    # generate a key with the given password and salt
    key = process_pwd(password, salt)
    # initialize the cipher
    cipher = AES.new(nonce=nonce, key=key, mode=AES.MODE_OCB)
    # decrypt the credentials
    data = cipher.decrypt_and_verify(ciphertext,tag)
    try: 
        # parse the data into json and make it readable
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        # if the decrypted credential data isn't valid
        raise IOError(f'data not valid: {str(err)}')
    return credentials

def save_and_exit(path: str, password: str, credentials: dict) -> None:
    '''
    Funciton that encrypts and saves some new credenntials

    ### PARAMETERS:
    - path: the file path where the credentials will be saved
    - password: the passphrase needed to encrypt the data
    - credentials: the actual data to encrypt and save
    '''
    # retrive the data of the given credentials, from json format to string
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    # generate salt and key
    salt = get_random_bytes(16)
    key = process_pwd(password, salt)
    # initialize the cipher
    cipher = AES.new(key=key, mode=AES.MODE_OCB)
    # encrypt the credentials
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(path, 'wb') as out_file:
        # save into the given path the encrypted credentials
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)


def search_and_add(query: str, dic: dict) -> dict:
    '''
    Search some credentials under a given query, if none is found may add new ones under that query

    ### PARAMETERS:
    - query: the query used to search the credentials
    - dic: the dicrionary containing the credentials

    ### RETURNS:
    Returns the used dictionary
    '''
    # search for the credentials
    if query in dic:
        # if found, print them
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        # if nothing is found, ask the user if it wants to add them
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            # if yes, ask for the credentials to add
            username_n = input('Insert username: ')
            password_n = getpass('Insert password: ')
            # add the credentials to the dictionary
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic


def log_in(username: str, password: str) -> None:
    '''
    Function that performs the login of the user to the app

    ### PARAMETERS:
    - username: the username of the user
    - password: the password of the user
    '''
    # initialize the BLAKE2b hash function
    h_obj  = BLAKE2b.new(digest_bits=512)
    # hashes the given username to get a pathfile
    path_file = h_obj.update(username.encode()).hexdigest()
    # check if a file with that name already exists
    if os.path.exists(path_file):
        # if it does, there is a user with that username
        try:
            # load the credentials in the file of the user
            credentials = load_data(path_file, password)
        except ValueError as err:
            # the password is wrong
            print('Autentication failed')
            return
        except IOError as err:
            # the decrypted data is invalid
            print('Error loading data:')
            print(err)
            return
    else:
        # if it doesn't, a user with that username does not exist
        # the program will ask the user if it wants to create a new username
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            # create a new user if yes
            credentials = {}
        else:
            # stop the program otherwise
            return

    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        # ask the user for a query to search the credential under that query
        query = input(prompt)
        if query != '':
            # search for the credentials
            credentials = search_and_add(query, credentials)
        else:
            # save and exit the app
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

# --------------------- MAIN --------------------- 
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':  
        # stop the program
        print('Goodbye!')
        exit()
    else:
        # perform the login
        password = getpass('Insert password: ')
        log_in(username, password)
