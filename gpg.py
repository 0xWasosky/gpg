import rsa
import pickle
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class File:
    @staticmethod
    def load_file(filename: str):
        with open(filename, "rb") as read_file:
            return read_file.read()

    @staticmethod
    def dump_file(filename: str, data: bytes) -> None:
        with open(filename, "wb") as write_file:
            write_file.write(data)
        return


class GPG:
    @staticmethod
    def generate_keys(key_size: int = 1028):
        return rsa.newkeys(key_size)
    
    @staticmethod
    def encrypt(aes_key: bytes) -> tuple[bytes, bytes]:
        keys = rsa.newkeys(1028)
        iv = secrets.token_bytes(16)
        aes = AES.new(aes_key, mode=AES.MODE_CBC, iv=iv)

        return aes.encrypt(pad(pickle.dumps(keys), 16)) + iv, keys[0].save_pkcs1()

    @staticmethod
    def decrypt(aes_key: bytes, data: bytes) -> tuple[rsa.PublicKey, rsa.PrivateKey]:
        keys = data[:816]
        iv = data[816:]

        aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)

        return pickle.loads(aes.decrypt(keys))
