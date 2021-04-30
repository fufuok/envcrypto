# -*- coding:utf-8 -*-
"""
    crypto.py
    ~~~~~~~~
    A safe way to store environmental Variables

    e.g.::

        Ref: main

    :author: Fufu, 2020/4/29
"""
import os
from base64 import urlsafe_b64encode
from hashlib import md5
from typing import Any

from cryptography.fernet import Fernet


def get_fernet_key(key: Any = None) -> bytes:
    """Any value generate fernet key (32 url-safe base64-encoded bytes)"""
    checksum = md5(bytes(str(key), encoding='utf-8'))
    a16 = checksum.digest()
    b16 = bytes(checksum.hexdigest(), encoding='utf-8')[8:24]
    return urlsafe_b64encode(a16 + b16)


def set_environ(varname: str = '', value: str = '', key: Any = None) -> str:
    """Set an environment variable (encrypt data)"""
    if key is not None:
        value = Encrypter(get_fernet_key(key)).encrypt(value)

    os.environ[varname] = value

    return value


def get_environ(varname: str = '', key: Any = None, default: str = '') -> str:
    """Get an environment variable (decrypt data)"""
    value = os.getenv(varname)
    if value is None:
        return default

    if key is not None:
        value = Encrypter(get_fernet_key(key)).decrypt(value)

    return value


class Encrypter(object):
    """Generate symetric keys and encrypt / decrypts them."""

    def __init__(self, key: bytes):
        self.fernet = Fernet(key)

    @classmethod
    def generate_key(cls):
        """Generate a random key."""
        return Fernet.generate_key()

    def encrypt(self, value: str) -> str:
        """Encrypt data."""
        return self.fernet.encrypt(value.encode('utf-8')).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a digest."""
        return self.fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')


if __name__ == '__main__':
    api_secret = 'AABB.Fufu@TEST001'
    env_name = 'APP_API_SECRET'
    my_key = b'\02S\n\t@k\x02'  # Any type and any length
    print('''
Set environment variable in your OS:
    export {0}={1}
In you code:
    data = {2!r}'''.format(
        env_name,
        set_environ(env_name, api_secret, my_key),
        get_environ(env_name, key=my_key),
    ))

    print('''
Set environment variable in your OS (if key is None):
    export {0}={1}
In you code:
    data = {2!r}'''.format(
        env_name,
        set_environ(env_name, api_secret),
        get_environ(env_name),
    ))
