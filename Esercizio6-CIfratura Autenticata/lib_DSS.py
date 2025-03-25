# import utility modules
from getpass import getpass
from base64 import b64decode
from binascii import Error as B64Error
import json
import sys
from crypto_utils import LibCryptoError, ReadProcessingError
from crypto_utils import read_file, write_file, check_len

# custom errors

class KeyImportError(LibCryptoError):
    '''
    Error importing a cryptographic key
    '''

class VerificationFailure(LibCryptoError):
    '''
    Verification of a signature failed
    '''

###
# SUPPORT FUNCTION
###

def get_passphrase() -> str:
    '''
    Function that acquires a non-empty passphrase
    for private key protection.

    ### Returns
    the passphrase as a string
    '''

    prompt = 'Insert password for the private key: '
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = 'Please enter a non-empty password: '


###
# CRYPTOGRAPHIC OPERATIONS
###

# PROTOTYPE
class DSS_cls():
    '''
    General class for digital signatures
    '''
    ##
    # class constants
    ##
    # name of digital signature algorithm
    ALGORTIHM: str
    # default file names for keys
    DEFAULT_SK: str
    DEFAULT_PK: str

    # Certification Authority's Public Key
    # hard-coded key, so no checks are necessary when importing
    CA_PK: str

    # data for security levels
    _SEC_LEVELS: dict[str, object] = {
        'medium': None, # mandatory element
        'high': None
    }
    def _check_level(self, level: str) -> None:
        '''
        Check a string describing a security level.
        
        ---
        ## Raises
        LibCryptoError if not admissible.
        '''
        if level not in self._SEC_LEVELS:
            err_msg = f'Error: security level "{level}" not recognized, '
            available = '", "'.join(self._SEC_LEVELS)
            err_msg += f'use one of: "{available}".'
            raise LibCryptoError(err_msg)

    ##
    # instance variable
    ##
    # cryptographic key
    _key = None
    
    def __init__(self) -> None:
        self._key = None

    def key_import(self, encoding: bytes, passphrase: str | None) -> None:
        '''
        Import a key, either public or secret.

        ### Parameters
        - encoding: the byte string representing the key
        - passphrase: optional string to unlock private keys

        ---
        ## Raises
        KeyImportError on failure
        '''
        raise NotImplementedError
    
    def check_security(self, level: str = 'medium') -> str:
        '''
        Check the security of the key set as instance variable.

        ### Parameter
        - level: string that describes the required security level,
            should be one of those defined in self._sec_levels.
        
        ### Returns
        an empty string if the key satisfies the required
        security level, otherwise it returns a string with an
        explanation of why the security level is not achieved.

        ---
        ## Raises
        LibCryptoError if the instance does not have
        a key set as instance variable or the level is not admissible.
        '''
        raise NotImplementedError
    
    def is_secret(self) -> bool:
        '''
        ### Returns
        - true if the key set as instance variable
        is a secret key;
        - false if it is a public key.

        ---
        ## Raises
        LibCryptoError if the instance does not have
        a key set as instance variable.
        '''
        raise NotImplementedError
    
    def generate(self, sec_level: str = 'medium') -> None:
        '''
        Generate a new key with the desired security level.
        
        ### Parameter
        - level: string that describes the desired security level,
            should be one of those defined in self._sec_levels.
        
        ### Sets
        the instance variable.
        
        ---
        ## Raises
        LibCryptoError if sec_level is not admissible.
        '''
        raise NotImplementedError
    
    def export_secret(self, passphrase: str) -> bytes:
        '''
        Export the secret key with an adequate level of protection.
        
        ### Parameter
        - passphrase: string used to protect the secret key,
            which can be successfully imported only providing
            the same passphrase.
        
        ### Returns
        the protected secret key encoded as a byte string.
        
        ---
        ## Raises
        LibCryptoError if the instance does not have 
        a secret key set as instance variable.
        '''
        raise NotImplementedError
    
    def export_public(self) -> bytes:
        '''
        Export the public part of the key set as instance variable.
        
        ### Returns
        the public key encoded as a byte string (encoding of an utf-8 string).
        
        ---
        ## Raises
        LibCryptoError if the instance does not have
        a key set as instance variable.
        '''
        raise NotImplementedError
    
    def sign(self,
            data: bytes, encode: bool = False) -> bytes | str:
        '''
        Function that computes a signature.
        
        ### Parameters
        - data: byte string to sign
        - encode: boolean that determines output type:
            - True: b64-utf8 encoded string
            - False: bytes (default)
        
        ### Returns
        the signature in the chosen format.
        
        ---
        ## Raises
        LibCryptoError if the instance does not have
        a secret key set as instance variable.
        '''
        raise NotImplementedError
    
    def verify(self,
            data: bytes, sig: bytes) -> bytes | str:
        '''
        Function that verifies a signature against the
        public key set as instance variable.

        ### Parameters
        - data: byte string of the data to verify
        - sig: byte string with the signature

        ---
        ## Raises
        - LibCryptoError if the instance does not have
        a key set as instance variable.
        - VerificationFailure if the verification fails.
        '''
        raise NotImplementedError
    
    def get_sig_size(self) -> int:
        '''
        Function that outputs the length in bytes of a signature,
        according to the key set as instance variable.
        
        ---
        ## Raises
        LibCryptoError if the instance does not have
        a key set as instance variable.
        '''
        raise NotImplementedError

##
# Higher level cryptographic functions
##

def import_key(
        data: bytes, is_private: bool, dss: DSS_cls) -> DSS_cls:
    '''
    Function that imports and validates a key.
    
    ### Parameters
    - data: byte string to check and import
    - is_private: boolean that tells if the key should be a private key
    - dss: instance of a DSS class that performs the import and saves the key
    
    ### Returns
    the updated instance of DSS.

    ---
    ## Raises
    ReadProcessingError if the import fails,
    or if the key has insufficient security,
    or if it is not a secret key when required.
    '''
    passphrase = None
    if is_private:
        # aquire passphrase
        passphrase = get_passphrase()
    # import key
    try:
        dss.key_import(data, passphrase)
    except KeyImportError as e:
        # error message
        message = 'Error while importing the key: ' + str(e)
        if is_private:
            message += '\nPlease check that the password is correct.'
        raise ReadProcessingError(message)
    # check security level, should be at least medium
    sec_error = dss.check_security()
    if sec_error != '':
        message = 'Error, insufficient secuirty: ' + sec_error
        raise ReadProcessingError(message)
    # check type
    if is_private and (not dss.is_secret()):
        raise ReadProcessingError(
            'Error: this is not a private key!')
    
    return dss

def read_key(is_private: bool, dss: DSS_cls) -> DSS_cls:
    '''
    Function that imports a key from file.
    
    ### Parameters
    - private: boolean that tells if the key is private
    - dss: instance of a DSS that performs the import and saves the key
    
    ### Returns the updated instance of DSS.

    ---
    ## Raises
    LibCryptoError if reading is aborted.
    '''
    # prepare settings
    settings = {
        'error': 'Key import aborted.',
        'process': lambda data: import_key(
                data,
                is_private,
                dss
            )
    }
    if is_private:
        settings['subject'] = 'private key'
        settings['default'] = dss.DEFAULT_SK
    else:
        settings['subject'] = 'public key'
        settings['default'] = dss.DEFAULT_PK

    dss, _ = read_file(**settings)
    return dss

# Public Key Infrastructure

class Certificate():
    '''
    Simplified certificate

    ### Instance variables
    - subject: string that identifies the subject
      associated to the public key
    - public_key: encoding of the public key of the subject
    - signature: signature by the Certification Authority
      that certifies the association between subject and key
      is None if the certificate has not been signed yet
    '''

    subject: str
    public_key: str
    signature: str | None

    def __init__(self, subject: str, public_key: str,
             signature: str | None = None) -> None:
        '''
        Initialize a new certificate to be signed.

        ### Parameters
        - subject: string that identifies the subject
        associated to the public key
        - public_key: encoding of the public key of the subject

        ### Sets
        The instance variables according to the parameters
        '''
        self.subject = subject
        self.public_key = public_key
        self.signature = signature
    
    def encode_for_sign(self) -> bytes:
        '''
        Compute the byte string used when signing or verifying
        the certificate.

        ### Returns
        a byte string with the concatenated encoding
        of the certificate data: subject + public_key.
        '''
        return self.subject.encode('utf-8') + self.public_key.encode('utf-8')
    
    def export(self) -> bytes:
        '''
        Export the certificate as byte string ready to be saved on file,
        encoded as a json file.

        ### Returns
        a byte string ready to be saved on file.
        '''
        return json.dumps(vars(self)).encode()
    
    def complete(self, ca_dss: DSS_cls) -> None:
        '''
        Complete the certificate with a signature.

        ### Parameters
        - ca_dss: instance of the DSS class initialized with the
        private key of the Certification Authority

        ### Sets
        The instance variable "signature"
        '''
        self.signature = ca_dss.sign(
            self.encode_for_sign(),
            encode = True
        )
    
    def verify(self, dss: DSS_cls) -> None:
        '''
        Verify the certificate against CA's public key.
        
        :Parameter:
        - dss: instance of a DSS that contains as class constant
          the public key of the Certification Authority.

        ---
        ## Raises
        VerificationFailure if the certificate does not validate
        against the CA public key of the given DSS class.
        '''
        err_str = 'Verification of certificate failed: '
        if self.signature is None:
            raise VerificationFailure(err_str + 'no signature')
        try:
            sig = b64decode(self.signature)
        except B64Error:
            err_str += 'the signature is not properly encoded'
            raise VerificationFailure(err_str)
        # use CA's PK
        # it is assumed to be correct so no checks are necessary
        dss.key_import(dss.CA_PK.encode(), passphrase = None)
        # verify certificate
        try:
            dss.verify(
                data = self.encode_for_sign(),
                sig = sig
            )
        except VerificationFailure as vf:
            err_str += str(vf)
            raise VerificationFailure(err_str) from vf


def import_cert(data: bytes) -> Certificate:
    '''
    Function that imports and validates a certificate.
    
    ### Parameters
    - data: byte string to check and import
    
    ### Returns
    a Certificate object
    
    ---
    ## Raises
    ReadProcessing error if the certificate is malformed
    or if  one of the non-optional field is missing.
    
    ### Note
    the content of the fields is not checked here,
    the certificate may not be signed yet
    '''
    error_msg = 'Certificate format not valid: '
    try:
        # decode as string and import as json
        cert_json = json.loads(data)
        # optional value: signature
        if 'signature' in cert_json:
            signature = cert_json['signature']
        else:
            signature = None
        # subject and public_key are mandatory values
        cert = Certificate(
            cert_json['subject'],
            cert_json['public_key'],
            signature
        )
    except ValueError:
        error_msg += 'encoding error.'
        raise ReadProcessingError(error_msg)
    except TypeError:
        error_msg += 'invalid data.'
        raise ReadProcessingError(error_msg)
    except KeyError as e:
        #certificate does not have one of the mandatory values
        error_msg += f'"{str(e)}" field not found.'
        raise ReadProcessingError(error_msg)
    return cert

#
# GENERATE KEYS
#

def gen_keys(dss: DSS_cls) -> None:
    '''
    Generate and save on file a new key pair.
    
    :Parameter:
    - dss: instance of a DSS that generates and saves the keys.
    
    ---
    ## Raises
    LibCryptoError if one of the writes is aborted.
    '''
    # generate key pair
    dss.generate()
    print('Keys generated!')
    # acquire passphrase
    passphrase = get_passphrase()
    # export secret and save on file
    settings = {
        'data': dss.export_secret(passphrase),
        'subject': 'secret key',
        'error': 'Secret key not saved: aborted.',
        'default': dss.DEFAULT_SK
    }
    out_file = write_file(**settings)
    print(f'Secret key correctly written in "{out_file}"')
    # export public key
    public_key = dss.export_public()
    # save on file
    settings = {
        'data': public_key,
        'subject': 'public key',
        'error': 'Public key not saved: aborted.',
        'default': dss.DEFAULT_PK
    }
    out_file = write_file(**settings)
    print(f'Public key correctly written in "{out_file}"')
    prompt = 'Insert identity to also save as a certificate, '
    prompt +='leave blank and press ENTER to skip\n'
    id_string = input(prompt)
    if id_string != '':
        # create and encode certificate
        cert = Certificate(
            subject = id_string,
            public_key = public_key.decode(),
        )
        settings = {
            'data': cert.export(),
            'subject': 'certificate',
            'error': 'Certificate not saved: aborted.',
            'default': id_string + '.cert'
        }
        out_file = write_file(**settings)
        print(f'Certificate correctly written in "{out_file}"')

#
# SIGN
#

def sign(dss: DSS_cls) -> None:
    '''
    Function that signs a file.
    
    :Parameter:
    - dss: instance of a DSS that manages key and signing.

    ---
    ## Raises
    LibCryptoError if reading or writing is aborted.
    '''
    # read private key to use
    dss = read_key(True, dss)

    # read file to sign, no validation
    settings = {
        'subject': '"data to sign"',
        'error': 'Signing aborted.'
    }
    data, in_file = read_file(**settings)

    #sign
    signature = dss.sign(data)
    # output 
    settings = {
        'data': signature + data,
        'subject': 'signed data',
        'error': 'Output aborted.',
        'default': in_file + '.sig'
    }
    out_file = write_file(**settings)
    print(f'Signed data correctly written in "{out_file}"')

def sign_cert(ca_dss: DSS_cls) -> None:
    '''
    Function that signs a certificate, completing it.
    
    :Parameter:
    - ca_dss: instance of a DSS
      intialized with the private key of the Certification Authority.

    ---
    ## Raises
    LibCryptoError if reading or writing is aborted.
    '''
    error = 'Signing aborted.'
    # read private key to use
    print('First let us initalize the Certification Authority')
    ca_dss = read_key(True, ca_dss)

    # read certificate to sign
    settings = {
        'subject': '"certificate to sign"',
        'error': error,
        'process': import_cert
    }
    cert: Certificate
    cert, cert_file = read_file(**settings)

    print('Certificate data:')
    print('Subject: ' + cert.subject)
    print('Public Key:\n' + cert.public_key)
    print('\nConfirm and sign?')
    c = input('(y to proceed, anything else to cancel): ')
    if c.lower() != 'y':
        raise LibCryptoError(error)
    # complete the certificate
    cert.complete(ca_dss)
    # write complete certificate, default overwrites old cert
    settings = {
        'data': cert.export(),
        'subject': 'signed certificate',
        'error': 'Certificate update aborted.',
        'default': cert_file
    }
    out_file = write_file(**settings)
    print(f'Signed certificate correctly written in "{out_file}"')

#
# VERIFY
#

def verify(dss: DSS_cls) -> None:
    '''
    Function that verifies a signed file.
    
    :Parameter:
    - dss: instance of a DSS that manages key and signing.

    ---
    ## Raises
    - VerificationFailure if verification fails.
    - LibCryptoError if reading or writing is aborted.
    '''
    # read public key to use
    dss = read_key(False, dss)

    # read signed file to verify, validating length
    sig_len = dss.get_sig_size()
    settings = {
        'subject': 'signed',
        'error': 'Verifying aborted.',
        'process': lambda data: check_len(data, sig_len)
    }
    data, in_file = read_file(**settings)

    # check signature
    dss.verify(data[sig_len:], data[:sig_len])
    # if there are no errors the signature is valid
    prompt = 'Signature is valid!\nExport content?'
    prompt += ' (y to confirm, anything else to cancel) '
    c = input(prompt)
    if c.lower() == 'y':
        # try to deduce original filename
        if in_file[-4:] == '.sig':
            default = in_file[:-4]
        else:
            default = in_file + '.ok'
        
        export_settings = {
            'data': data[sig_len:],
            'subject': 'content data',
            'error': 'Data export aborted',
            'default': default
        }
        out_file = write_file(**export_settings)
        print('Data correctly written in "' + out_file + '"')

def verify_cert(dss: DSS_cls) -> None:
    '''
    Function that verifies a certificate.
    
    :Parameter:
    - dss: instance of a DSS that manages key and signing.

    ---
    ## Raises
    LibCryptoError if reading or writing is aborted.
    '''
    # read certificate to verify
    settings = {
        'subject': '"certificate to verify"',
        'error': 'Verification aborted.',
        'process': import_cert
    }
    cert: Certificate
    cert, _ = read_file(**settings)
    # verify signature of certificate against CA's Public Key
    # which is hardcoded in the DSS class
    try:
        cert.verify(dss)
        print('OK: the certificate is valid.')
    except VerificationFailure as vf:
        print(f'The certificate is not valid!\n{vf}')
    return


###
# MAIN DSS SCRIPT
###

def dss_script(dss: DSS_cls) -> None:
    '''
    Main function that manages DSS operations.
    
    ### Parameter
    - dss: instance of a DSS that implements all operations.
    '''
    # set prompt
    main_prompt = f'''[Digital Signatures with {dss.ALGORTIHM}] What do you want to do?
1 -> generate and save keys
2 -> sign a file
3 -> verify a signed file
4 -> sign a certificate
5 -> verify a certificate
0 -> quit
-> '''
    while True:
        #get user's choice and call appropriate function
        #errors are captured and printed out
        #invalid choices are ignored
        choice = input(main_prompt)
        try:
            if choice == '1':
                    gen_keys(dss)
            elif choice == '2':
                    sign(dss)
            elif choice == '3':
                    verify(dss)
            elif choice == '4':
                    sign_cert(dss)
            elif choice == '5':
                    verify_cert(dss)
            elif choice == '0':
                sys.exit()
        except LibCryptoError as e:
                print(e)