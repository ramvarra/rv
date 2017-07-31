'''
Cryptography Utility Module
Author: Ram Varra
Requires: pycrypto, keyring, paramiko
'''
import Crypto.Cipher.AES
import Crypto.Random
import keyring
import paramiko
import base64
import hashlib
import struct
import logging
import tempfile
import subprocess
import os
import io

#-------------------------------------------------------------------------------------------------------------------
class Crypt:
    _IV_LEN = 16
    _INT_SIZE = struct.calcsize("!I")
    _SALT = b'\xa3\xf2\xf9F\xfa\x7f"\x83\xff\xb4\x9e\x0e\xf1\x8aN\xba\xf5\x9eI\xdf\x06\x8e\x13\xa1.\x17U\xed\xef\xed\xbbA'
    #-------------------------------------------------------------------------------------------------------------------
    def aes_encrypt(self, key, data, salted=False):
        assert isinstance(key, bytes), "key must be bytes type"
        assert isinstance(data, bytes), "data must be bytes type"

        iv = Crypto.Random.get_random_bytes(self._IV_LEN)
        if salted:
            key += self._SALT
        aes_key = hashlib.sha256(key).digest()
        data_length = len(data)
        payload_length = data_length + self._INT_SIZE
        pad_length = (16 - payload_length % 16) % 16
        payload = struct.pack("!I{}s".format(data_length + pad_length), data_length, data)
        encrypter = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_CBC, IV=iv)
        return iv + encrypter.encrypt(payload)
    #-------------------------------------------------------------------------------------------------------------------
    def aes_decrypt(self, key, cipher_text, salted=False):
        assert isinstance(key, bytes), "key must be bytes type"
        assert isinstance(cipher_text, bytes), "cipher_text must be bytes type"

        iv = cipher_text[:16]
        cipher_text = cipher_text[16:]
        if salted:
            key += self._SALT
        aes_key = hashlib.sha256(key).digest()
        decrypter = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_CBC, IV=iv)
        payload = decrypter.decrypt(cipher_text)
        data_length, = struct.unpack("!I", payload[:self._INT_SIZE])
        return payload[self._INT_SIZE : self._INT_SIZE + data_length]
    #-------------------------------------------------------------------------------------------------------------------
    def aes_encrypt_string(self, key, data, encoding='utf8', **kwargs):
        assert isinstance(key, str), "key must be utf8 string"
        assert isinstance(data, str), "data must be utf8 string"
        return self.aes_encrypt(key.encode(encoding), data.encode(encoding), **kwargs)
    #-------------------------------------------------------------------------------------------------------------------
    def aes_decrypt_string(self, key, cipher_text, encoding='utf8', **kwargs):
        assert isinstance(key, str), "key must be utf8 string"
        assert isinstance(cipher_text, bytes), "cipher_text must be bytes"
        d = self.aes_decrypt(key.encode(encoding), cipher_text, **kwargs)
        return d.decode(encoding)
    #-------------------------------------------------------------------------------------------------------------------
    def keyring_set(self, service_name, user_name, password, encoding='utf8', **kwargs):
        assert isinstance(service_name, str), "service_name must be utf8 string"
        assert isinstance(user_name, str), "user_name must be utf8 string"
        assert isinstance(password, str), "password must be utf8 string"
        # encrypt data using name/user as keys
        aes_key = service_name + user_name
        data_to_store = base64.b64encode(self.aes_encrypt_string(aes_key, password, encoding=encoding, **kwargs)).decode('ascii')
        keyring.set_password(service_name, user_name, data_to_store)
    #-------------------------------------------------------------------------------------------------------------------
    def keyring_get(self, service_name, user_name, encoding='utf8', **kwargs):
        assert isinstance(service_name, str), "service_name must be utf8 string"
        assert isinstance(user_name, str), "user_name must be utf8 string"

        # get data from keyring and decrypt data name/user as keys
        aes_key = service_name + user_name
        encrypted_password = base64.b64decode(keyring.get_password(service_name, user_name))
        return self.aes_decrypt_string(aes_key, encrypted_password, encoding=encoding, **kwargs)

    #----------------------------------------------------------------------------------------------------------------------------
    def run_ssh_command(self, cmd, ssh_pkey_file, keyring_name, keyring_user, temp_file_life_time=15, **kwargs):
        '''
        Run a ssh command that uses a key file protected with pass phrase. Gets the passphrase info from keyring.
        The command must not request any other inputs.

        cmd: string command with a placeholder for PKEY FILE. e.g. "ssh -i '{SSH_PKEY_FILE}'"
        ssh_pkey_file: OpenSSH Private Key File protected with passphrase.
        keyring_name: keyring network name containg the passphrase
        keyring_name: keyring user name containing the passphrase
        temp_file_life_time: how long to keep temp pkey file after launcing the command in seconds
        kwargs: args to pass to Popen
        returns: Popen object
        '''

        assert temp_file_life_time > 0, "temp_file_life_time must be > 0 seconds"
        pkey_file_password = self.keyring_get(keyring_name, keyring_user, salted=True)
        #load private key
        pkey = paramiko.RSAKey.from_private_key_file(ssh_pkey_file, password=pkey_file_password)

        with tempfile.NamedTemporaryFile(mode='w', prefix='twinkle_', suffix='.jpg') as tfd:
            pkey.write_private_key(tfd)
            tfd.flush()
            #logging.info("TF: {}".format(tfd.name))
            cmd_to_run = cmd.format(SSH_PKEY_FILE=tfd.name)
            logging.info("Running: {}".format(cmd_to_run))
            proc = subprocess.Popen(cmd_to_run, shell=True, **kwargs)
            # wait upto temp_file_life_time secs to let the temp file to disappear. If proc is done, we will exit sooner
            try:
                proc.wait(timeout=temp_file_life_time)
            except subprocess.TimeoutExpired:
                pass
            # erase the temp_file contents by writing random bytes over it.
            tfd.seek(0, os.SEEK_END)
            file_size = tfd.tell()
            tfd.seek(0, os.SEEK_SET)
            tfd.write(base64.b64encode(Crypto.Random.get_random_bytes(file_size)).decode('ascii'))
            tfd.flush()

        #file_check("Before RET", tfd.name)
        return proc
    #-------------------------------------------------------------------------------------------------------------------
    def sha256_file(self, file_name):

        chunk_size = 64*1024
        hasher = hashlib.sha256()
        with io.open(file_name, 'rb') as fd:
            buf = fd.read(chunk_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = fd.read(chunk_size)
        return hasher.hexdigest()

#-------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    key = 'superflgisticsexpeal'
    secret = 'hello world'
    service_name = 'rv.crypt.test'

    crypt = Crypt()

    for salted in (True, False):
        print ("AES Encrypt/Decrypt Test (Salted: {}) - ".format(salted), end='')
        print(["FAILED", "OK"][crypt.aes_decrypt_string(key, crypt.aes_encrypt_string(key, secret, salted=salted), salted=salted) == secret])

        user_name = "{}_salted_{}".format(service_name, salted)
        print ("KEYRING_SET Test (Salted: {}) - ".format(salted), end='')
        crypt.keyring_set(service_name, user_name, secret, salted=salted)
        print ("OK")

        print ("KEYRING_GET Test (Salted: {}) - ".format(salted), end='')
        print(["FAILED", "OK"][crypt.keyring_get(service_name, user_name, salted=salted) == secret])

