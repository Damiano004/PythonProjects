# import utility modules
from os.path import isfile

# custom errors for precise exception management

class LibCryptoError(Exception):
    '''
    Error executing cryptographic script
    '''

class ReadProcessingError(LibCryptoError):
    '''
    Error preprocessing data read from file
    '''

class KeyImportError(LibCryptoError):
    '''
    Error importing a cryptographic key
    '''

###
# INPUT/OUTPUT functions
###

def read_file(
            subject : str, error: str, default: str ='',
            process = lambda data: data
        ) -> tuple[object, str]:
    '''
    Function that reads and pre-processes files.
    
    ### Parameters
    - subject: string that describes what the file should contain
    - error: error message to show when aborting
    - default: name of file to open if not specified
    - process: function to call on data,
    reading is not considered complete unless
    this function is called successfully.
    Should raise ReadProcessingError on errors.
    If not specified the identity function is used.
    
    ### Returns
    data read (and processed) and name of file read.

    ---
    ## Raises
    LibCryptoError if user aborts reading.
    '''
    #prepare string to print, including default choice
    prompt = f'Insert path to {subject} file'
    if default != '':
        prompt += f' ({default})'
    prompt += ':\n'
    #try until file is correctly read or user aborts
    while True:
        #read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        #read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print(f'Error while reading {subject}:\n{e}')
            #let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                #abort
                raise LibCryptoError(error)

def write_file(
            data: bytes, subject: str,
            error: str, default: str =''
        ) -> str:
    '''
    Function that writes data on file.
    
    ### Parameters
    - data: byte string to write to file
    - subject: description of what the file will contain
    - error: error message to show when aborting
    - default: name of file to open if not specified
    
    ### Returns
    Name of file written.

    ---
    ## Raises
    LibCryptoError if user aborts writing.
    '''
    #try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = f'Insert path to file where to save {subject}'
        if default != '':
            prompt += f' ({default})' 
        prompt += ':\n'
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
        try:
            # warn before overwriting
            if isfile(out_filename):
                prompt = 'File exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue
            # write data
            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        except IOError as e:
            print(f'Error while saving {subject}: {e}')
            # let user abort writing file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise LibCryptoError(error)

###
# VALIDATION FUNCTIONS
###

def check_len(data: bytes, min_len: int) -> bytes:
    '''
    Function that validates a byte string's minimum length.
    
    ### Parameters
    - data: byte string to check
    - min_len: minimum length in bytes the file must have
    
    ### Returns
    The input data if the condition is satisfied.
    
    ---
    ## Raises
    ReadProcessingError if the condition is not satisfied.
    '''
    if len(data) >= min_len:
        return data
    else:
        message = f'Error: the file must be at least {min_len} bytes long.'
        raise ReadProcessingError(message)