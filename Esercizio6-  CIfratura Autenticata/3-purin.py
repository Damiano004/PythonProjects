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

TAG_LENGTH = 16
NONCE_LEN = 16

def gen_keys() -> None:
    dss = EdDSA_DSS()
    print("Generating keys...")
    dss.generate()
    print("keys succesfully generated!")
    passPhrase = get_passphrase()
    settings = {
        'data': dss.export_secret(passPhrase),
        'subject': 'secret key',
        'error': 'Secret key not saved: aborted',
        'default': dss.DEFAULT_SK
    }
    out_file = write_file(**settings)
    print(f'Secret key is written in {out_file}')
    prompt = 'Insert identity to also save as a certificate, '
    id_string = input(prompt)
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
    out_file = write_file(**settings)
    print(f'Certificate key is written in {out_file}')

def kdf(x):
        return SHAKE128.new(x).read(32)

def encrypt():
    # read certificate to sign
    settings = {
        'subject': '"certificate"',
        'error': 'aborted.',
        'process': import_cert
    }
    cert: Certificate
    cert, _ = read_file(**settings)

    dss = EdDSA_DSS()
    dss = read_key(True,dss)
    dss2 = EdDSA_DSS()
    dss2 = import_key(cert.public_key.encode(),False,dss2)
    print(dss2._key)
    session_key = key_agreement(static_priv=dss._key, static_pub=dss2._key, kdf=kdf)
    print(session_key)
    
    settings = {
        'subject': '"plaintext"',
        'error': 'reading aborted.'
    }
    pt, _ = read_file(**settings)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(session_key,nonce=nonce, mode=AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(pt)
    ciphertext = tag + nonce + ct
    settings = {
        'data' : ciphertext,
        'subject' : 'ciphertext',
        'error' : 'User aborted writing the output',
        'default' : 'ciphertext.bin'
    }
    out_file = write_file(**settings)
    print("File written in "+out_file)

def decrypt():
    settings = {
        'subject': '"ciphertext"',
        'error': 'reading aborted.'
    }
    ct, _ = read_file(**settings)
    tag = ct[:TAG_LENGTH]
    nonce = ct[TAG_LENGTH:TAG_LENGTH+NONCE_LEN]
    ciphertext = ct[TAG_LENGTH+NONCE_LEN:]
    settings = {
        'subject': '"certificate"',
        'error': 'aborted.',
        'process': import_cert
    }
    cert: Certificate
    cert, _ = read_file(**settings)

    dss = EdDSA_DSS()
    dss = read_key(True,dss)
    dss2 = EdDSA_DSS()
    dss2 = import_key(cert.public_key.encode(),False,dss2)
    print(dss2._key)
    session_key = key_agreement(static_priv=dss._key, static_pub=dss2._key, kdf=kdf)
    print('nonce:')
    print(nonce)
    print('tag:')
    print(tag)
    print('ct:')
    print(ciphertext)
    cipher = AES.new(key=session_key,nonce=nonce, mode=AES.MODE_GCM)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    settings = {
        'data' : plaintext,
        'subject' : 'plaintext',
        'error' : 'User aborted writing the output',
        'default' : 'plaintext.txt'
    }
    write_file(**settings)

encrypt()
decrypt()