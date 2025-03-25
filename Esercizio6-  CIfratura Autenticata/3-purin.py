from crypto_utils import LibCryptoError, ReadProcessingError
from crypto_utils import read_file, write_file, check_len
from lib_DSS import VerificationFailure, Certificate
from lib_DSS import get_passphrase, import_cert, import_key
from lib_DSS import read_key
from libEdDSA import EdDSA_DSS
from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement
from Crypto.Random import get_random_bytes

# ---------- CONSTANTS DEFINITION ----------#
TAG_LEN = 16                                #
NONCE_LEN = 15                              #
KEY_LEN = 112                               #
TOT_LEN = TAG_LEN+NONCE_LEN+KEY_LEN         #
# ------------------------------------------#

def gen_keys() -> None:
    '''
    Function that generates and saves keys and a certificate
    '''
    # initialize an EdDSA_DSS object
    dss = EdDSA_DSS()
    print("Generating keys...")
    # generate keys
    dss.generate()
    passPhrase = get_passphrase()
    settings = {
        'data': dss.export_secret(passPhrase),
        'subject': 'secret key',
        'error': 'Secret key not saved: aborted',
        'default': dss.DEFAULT_SK
    }
    # write private key on file
    write_file(**settings)
    print("keys succesfully generated!")
    prompt = 'Insert identity to also save as a certificate: '
    id_string = input(prompt)
    # create a certificate
    cert = Certificate(
        subject = id_string,
        public_key= dss.export_public().decode()
    )
    settings = {
        'data': cert.export(),
        'subject': 'certificate',
        'error': 'Certificate not saved: aborted.',
        'default': id_string + '.cert'
    }
    # write certificate on file
    out_file = write_file(**settings)
    print(f'Certificate key is written in {out_file}')

def kdf(x):
        '''
        Key derivation function used for key agreement
        '''
        return SHAKE128.new(x).read(16)

def encrypt() -> None:
    '''
    Function tat performs the encryption
    '''
    settings = {
        'subject': '"certificate"',
        'error': 'aborted.',
        'process': import_cert
    }
    # initialize certificate
    cert: Certificate
    dss = EdDSA_DSS()
    # certificate validation
    while True:
        cert, _ = read_file(**settings)
        try:
            cert.verify(EdDSA_DSS())
            break
        except VerificationFailure:
            print('Certificate is not valid.')
            user_input = input('insert q to exit or anything else to try again')
            if(user_input == 'q'):
                raise LibCryptoError('User aborted the insertion of the certificate')

    # retrive public key from certificate
    pub_key = cert.public_key
    dss_pub = import_key(pub_key,False,dss)
    # generate an ephimeral private and public key
    dss.generate()
    # create a session key
    session_key = key_agreement(static_pub=dss_pub._key,eph_priv=dss._key,kdf=kdf)

    settings = {
        'subject': '"plaintext"',
        'error': 'reading aborted.'
    }
    # read the plaintext
    pt, _ = read_file(**settings)
    # generate nonce
    nonce = get_random_bytes(NONCE_LEN)

    # initialize the cipher
    cipher = AES.new(session_key,nonce=nonce, mode=AES.MODE_OCB)
    # encrypt the plaintext
    ct, tag = cipher.encrypt_and_digest(pt)
    # add the ephimeral public key, the nonce and the tag to the ciphertext
    ciphertext = dss.export_public() + nonce + tag  + ct

    settings = {
        'data' : ciphertext,
        'subject' : 'ciphertext',
        'error' : 'User aborted writing the output',
        'default' : 'ciphertext.txt.enc'
    }
    # write ciphertext on file
    out_file = write_file(**settings)
    print("File written in "+out_file)

def decrypt() -> None:
    '''
    Function that performs the decryption
    '''
    settings = {
        'subject': '"ciphertext"',
        'error': 'reading aborted.',
        'process': lambda raw: check_len(data=raw, min_len=TOT_LEN)
    }
    # read the ciphertext file
    ct, _ = read_file(**settings)

    # extract the components used to decrypt
    pub_key = ct[:KEY_LEN]
    nonce = ct[KEY_LEN:KEY_LEN+NONCE_LEN]
    tag = ct[KEY_LEN+NONCE_LEN:TOT_LEN]
    ciphertext = ct[TOT_LEN:]
    
    try:
        # ask the user for the private key
        priv_key = read_key(True,EdDSA_DSS())
        # create the session key
        session_key = key_agreement(eph_pub=pub_key,static_priv=priv_key,kdf=kdf)
        # initialize the cipher
        cipher = AES.new(key=session_key,mode=AES.MODE_OCB, nonce=nonce)
        # decrypt the ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise LibCryptoError('Error while executing the decryption.')
    
    settings = {
        'data' : plaintext,
        'subject' : 'plaintext',
        'error' : 'User aborted writing the output',
        'default' : 'plaintext.txt'
    }
    # write the file
    write_file(**settings)

prompt = '''What do you want to do?
    1 -> generate and save keys
    2 -> encrypt
    3 -> decrypr
    0 -> quit
 -> '''
while True:
    try:
        # get user's choice and call appropriate function
        choice = input(prompt)
        match choice:
            case '1':
                gen_keys()
            case '2':
                encrypt()
            case '3':
                decrypt()
            case '0':
                print('Bye Bye')
                exit()
            case _:
                # default error message for wrong inputs
                print('Invalid choice, please try again!')
    except (LibCryptoError, ReadProcessingError) as err:
        print(err)