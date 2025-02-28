from crypto_utils import LibCryptoErrorr, KeyImportError, ReadProcessingError
from crypto_utils import read_file, write_file, check_len
from lib_DSS import DSS_cls
from Crypto.PublicKey import ECC
from Signature import eddsa
from Crypto.Hash import SHAKE256

class EdDSA_cls(DSS_cls):
    
    _key: ECC.EccKey | None

    CA_PK = "nMCowBQYDK2VwAyEAqOE0vX/kv7hgxE+D+oMwP42u3z1XG4fUZbYmsrptFTE="

    def key_import(self, encoding: bytes, passphrase: str | None):
        try:
            self._key = ECC.import_key(encoding,passphrase)
        except ValueError as e:
            raise KeyImportError(e) from e

    def sign(self, data, encode = False):
        signer = eddsa.new(self._key, 'rfc8032')
        signature = 