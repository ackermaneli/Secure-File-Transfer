"""
TransferIt server
helper.py
description: contains helper function to deal with server operations (file / encryption / parsing / more)
"""

from Crypto.Random import get_random_bytes  # generate AES key
from Crypto.Cipher import PKCS1_OAEP  # for AES key encryption with client public key
from Crypto.PublicKey import RSA  # for import public key
from Crypto.Cipher import AES  # for decryption of client file contents
from Crypto.Util.Padding import unpad  # for un padding unnecessary bytes from the file content decryption
import crc  # for file content CRC calculation (linux cksum command)
from pathlib import Path  # for directory creation / file storage / file deletion
import networkProtocol

DEFAULT_PORT = 1234


def gen_aes(public_key):
    """ generate aes key (16 bytes) and encrypt it with the given public key
        public key is assumed to be 160 bytes valid key
        Return aes key && encrypted aes key on success
        Return None & None on failure"""
    try:
        aes_key: bytes = get_random_bytes(networkProtocol.CLT_SYMMETRICKEY_SIZE)
        temp = aes_key
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext: bytes = cipher.encrypt(temp)  # encrypted AES key
        return aes_key, ciphertext
    except Exception as e:
        print(f"AES key creation & encryption process failed *publicKey request* {e} ")
        return None, None


def decrypt_content(aes_key, encrypted_content):
    """ given an aes key and a content which was encrypted with the aes key, decrypt the content
        Return decrypted content on success
        Return None on failure"""
    try:
        iv: bytes = bytes([0] * networkProtocol.CLT_SYMMETRICKEY_SIZE)  # in a real system this never should be all 0's
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted: bytes = unpad(cipher.decrypt(encrypted_content), AES.block_size)
        return decrypted
    except Exception as e:
        print(e)
        return None


def calc_crc(content):
    """ Calc CRC of a for a given content, CRC calculated identically to Linux cksum command
        Return CRC on success
        Return None on failure """
    try:
        digest = crc.crc32()
        digest.update(content)
        cksum: int = digest.digest()
        return cksum
    except Exception as e:
        print(e)
        return None


def create_dir(dir_name):
    """ attempt to create a directory with a given name in the current working directory.
        if the directory already exists NOT throw an exception and still return True
        dir_name is assumed to come in bytes (taken from database) and shall be decoded,
        the dir_name is assumed to be the client username, thus decoded in utf-8.
        Return directory path on success
        Return None on failure"""
    try:
        curr_path = str(Path.cwd())
        # create directory if not exists, if exists NOT throws an exception (exist_ok=True)
        dir_path: str = curr_path + '\\' + dir_name.decode('utf-8')
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        return dir_path
    except Exception as e:
        print(e)
        return None


def store_file(file_content, dir_path, file_name):
    """ attempt to store a given file content in a given directory path with a given file name.
        if the file already exists, overwrite it
        Return file path on success
        Return None on failure """
    try:
        file_path: str = dir_path + "\\" + file_name
        p = Path(file_path)
        p.write_bytes(file_content)
        return file_path
    except Exception as e:
        print(e)
        return None


def delete_file(file_path):
    """ attempt to delete a file given a file path
        Return True on success
        Return False on failure"""
    try:
        Path(file_path).unlink()
        return True
    except Exception as e:
        print(e)
        return False


def acquire_port(file_path):
    """
    Attempt to read port from file_path.
    Only the 1st line will be read.
    Return int(port) on success
    Return DEFAULT_PORT on failure
    """
    port: int = DEFAULT_PORT
    try:
        p = Path(file_path)
        with p.open() as f:
            port = f.readline().strip()
            port = int(port)
    except Exception as e:
        port = DEFAULT_PORT
    finally:
        return port
