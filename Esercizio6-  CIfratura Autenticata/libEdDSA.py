#!/usr/bin/python3
# --Digital Signature with EdDSA--

# import cryptography modules
from base64 import b64encode
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from lib_DSS import LibCryptoError, KeyImportErrorr
from lib_DSS import VerificationFailure, DSS_cls
from lib_DSS import dss_script

class EdDSA_DSS(DSS_cls):
    '''
    Class that implements the signing functionalities
    with EdDSA
    '''
    ALGORTIHM = 'EdDSA'
    DEFAULT_PK = 'eddsa_pk.pem'
    DEFAULT_SK = 'eddsa_sk.pem'
    # define bit sizes for different security levels
    _SEC_LEVELS = {
        'medium': ['Ed25519', 'Ed448'],
        'high': ['Ed448']
    }
    # define CA's PK
    CA_PK = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqOE0vX/kv7hgxE+D+oMwP42u3z1XG4fUZbYmsrptFTE=\n-----END PUBLIC KEY-----"
    # set correct class for the key
    _key: ECC.EccKey | None

    def key_import(self,
            encoding: bytes, passphrase: str | None) -> None:
        # use library's import method, wrap to raise correct error
        try:
            self._key = ECC.import_key(encoding, passphrase)
        except ValueError as e:
            raise KeyImportErrorr(e) from e
    
    def check_security(self, level: str = 'medium') -> str:
        # check that a key has been set
        if self._key is None:
            raise LibCryptoError('Error: no key set')
        # check correctness of parameter
        self._check_level(level)
        # compare parameters of key with the security level
        key_curve = self._key.curve
        ok_curves = self._SEC_LEVELS[level]
        # if security is met, the warning message is empty
        warning = ''
        # security level not satisfied, prepare warning message
        if not key_curve in ok_curves:
            warning += f'the curve of the key ({key_curve})'
            warning += f' does not provide a {level} level of '
            warning += 'security, the smallest curve is '
            warning += f'{ok_curves[0]}'
        # return waring message
        return warning
    
    def is_secret(self) -> bool:
        # check that a key has been set
        if self._key is None:
            raise LibCryptoError('Error: no key set')
        # check that the key has the private components
        return self._key.has_private()
    
    def generate(self, sec_level: str = 'medium') -> None:
        # check correctness of parameter
        self._check_level(sec_level)
        # generate new keypair with proper parameters
        self._key = ECC.generate(
            curve    = self._SEC_LEVELS[sec_level][0]
        )
    
    def export_secret(self, passphrase: str) -> bytes:
        # check that a secret key has been set
        if not self.is_secret():
            raise LibCryptoError('Error: no secret key set')
        # define export settings
        # see https://www.pycryptodome.org/src/io/pkcs8
        # and use the recommendations seen in class,
        # see also https://www.pycryptodome.org/src/protocol/kdf
        export_settings = {
            'format': 'PEM',
            'passphrase': passphrase,
            'protection': 'scryptAndAES128-GCM',
            'prot_params': {
                'iteration_count': 2**20
            }
        }
        # explicitly encode to bytes
        return self._key.export_key(
            **export_settings
        ).encode()
    
    def export_public(self) -> bytes:
        # check that a key has been set
        if self._key is None:
            raise LibCryptoError('Error: no key set')
        # extract public, export and explicitly encode to bytes
        return self._key.public_key().export_key(
            format = 'PEM'
        ).encode()
    
    def sign(self,
            data: bytes, encode: bool = False) -> bytes | str:
        if not self.is_secret():
            raise LibCryptoError('Error: no secret key set')
        # initialise signing
        signer = eddsa.new(self._key, 'rfc8032')
        # sign
        sig = signer.sign(data)
        # encode and return signature
        if encode:
            sig = b64encode(sig).decode('utf-8')
        return sig
    
    def verify(self,
            data: bytes, sig: bytes) -> bytes | str:
        if self._key is None:
            raise LibCryptoError('Error: no key set')
        # initialise verifying
        verifier = eddsa.new(self._key, 'rfc8032')
        # verify
        try:
            verifier.verify(data, sig)
        except ValueError as e:
            raise VerificationFailure('invalid signature') from e
    
    def get_sig_size(self) -> int:
        if self._key is None:
            raise LibCryptoError('Error: no key set')
        return 2 * self._key.pointQ.size_in_bytes()

if __name__ == "__main__":
     dss_script(EdDSA_DSS())