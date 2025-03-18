from crypto_utils import LibCryptoError, ReadProcessingError
from crypto_utils import read_file, write_file, check_len
from lib_DSS import VerificationFailure, Certificate
from lib_DSS import get_passphrase, import_cert, import_key
from lib_DSS import read_key
from libEdDSA import EdDSA_DSS

def gen_keys() -> None:
    # print("Generating keys...")
    # EdDSA_DSS.generate(self=EdDSA_DSS)
    # print("keys succesfully generated!")
    # passPhrase = get_passphrase()
    # settings = {
    #     'data': EdDSA_DSS.export_secret(passPhrase),
    #     'subject': 'secret key',
    #     'error': 'Secret key not saved: aborted',
    #     'default': EdDSA_DSS.DEFAULT_SK
    # }
    # out_file = write_file(**settings)
    # print(f'Secret key is written in {out_file}')
    # pub_key = EdDSA_DSS.export_public()
    # settings = {
    #     'data': pub_key,
    #     'subject': 'public key',
    #     'error': 'Public key not saved: abort',
    #     'default': EdDSA_DSS.DEFAULT_PK
    # }
    # out_file = write_file(**settings)
    # print(f'Public key is written in {out_file}')
    prompt = 'Insert identity to also save as a certificate, '
    prompt +='leave blank and press ENTER to skip\n'
    id_string = input(prompt)
    if id_string != '':
        cert = Certificate(
            subject = id_string,
            public_key= "pub_key"
        )
        settings = {
            'data': cert.export(),
            'subject': 'certificate',
            'error': 'Certificate not saved: aborted.',
            'default': id_string + '.cert'
        }
        out_file = write_file(**settings)
        print(f'Certificate key is written in {out_file}')


gen_keys()