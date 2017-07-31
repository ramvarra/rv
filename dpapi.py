import os
import tempfile
import clr
import System.Security.Cryptography as sc
import pickle
import io

CURRENT_USER = sc.DataProtectionScope.CurrentUser
LOCAL_MACHINE = sc.DataProtectionScope.LocalMachine

#==========================================================================================
def encrypt_to_bytes(secret, scope=CURRENT_USER):
    '''
        Encrypts a picklable python object and encrypts using DPAPI.
    :param secret:  Pickalable python object. ANy object that can successfully run through pickle.dumps()
    :param scope: either rv.dpapi.CURRENT_USER or rv.dpapi.LOCAL_MACHINE
    :return: returns encrypted bytes as bytearray.
    '''
    bytes = sc.ProtectedData.Protect (pickle.dumps(secret), None, scope)
    return bytearray(bytes)
#==========================================================================================
def encrypt_to_file(secret, file_name, **kwargs):
    '''
        Encrypts a picklable python object and encrypts using DPAPI and writes to file.
    :param secret:  Pickalable python object. ANy object that can successfully run through pickle.dumps()
    :param file_name: Output file. If file exists, it WILL BE OVERWRITTEN.
    :param kwargs: Pass scope argument as defined in encrypt_to_bytes()
    :return: None
    '''
    bytes = encrypt_to_bytes (secret, **kwargs)
    io.open(file_name, 'wb').write(bytes)


#==========================================================================================
def decrypt_from_bytes(bytes, scope=CURRENT_USER):
    '''
    Decrypts previously encrypted bytes into a python object.
    :param bytes: bytes to decrypt. Must be a bytearray returned from encrypt_to_bytes()
    :param scope: Must match the scope used while encrypting.
    :return: python object decrypted
    '''
    bytes = bytearray(sc.ProtectedData.Unprotect (bytes, None, scope))
    return pickle.loads(bytes)

#==========================================================================================
def decrypt_from_file(file_name, **kwargs):
    '''
        Decrypts contents of file_name and returns python object.
    :param file_name: Input file. Must have been created by encrypt_to_file()
    :param kwargs: Pass scope argument as defined in decrypt_from_bytes()
    :return: None
    '''
    bytes = io.open(file_name, 'rb').read()
    return decrypt_from_bytes (bytes, **kwargs)

#==========================================================================================
if __name__ == '__main__':
    secret = {'str_value': r'ABCD23939CCKJDJ393(*!@^_#))22-4AB1291kdjfkdjkdbebkdei3991-k3-&&)_#',
              'int_value': 1092939,
              'float_value': 1294e5,
              'list_value': ['hello', 'world', 10, 20.4],
              'dict_value': {'k1': 'v1', 'k2': 201, 'k3': 20.5}
              }
    fd, file_name = tempfile.mkstemp(suffix='.sec', prefix='dpapi_test_')
    os.close(fd)
    print ("Using file: {}".format (file_name))
    try:
        for scope in [CURRENT_USER, LOCAL_MACHINE]:
            print ("Testing encrypt/decrypt to bytes scope: {}".format (scope))
            assert secret == decrypt_from_bytes (encrypt_to_bytes (secret, scope=scope)), "ENCRYPT/DECRYPT FAILURE"
            print ("ENC/DEC TO BYTES OK")

            print ("Testing encrypt/decrypt to FILE scope: {}".format (scope))
            encrypt_to_file (secret, file_name, scope=scope)
            assert secret == decrypt_from_file (file_name, scope=scope), "ENCRYPT/DECRYPT FILE FAILURE"
            print ("ENC/DEC TO FILE OK")
    finally:
        os.remove(file_name)