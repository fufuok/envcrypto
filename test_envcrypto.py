# -*- coding:utf-8 -*-
"""
    test_envcrypto.py
    ~~~~~~~~

    :author: Fufu, 2021/5/6
"""
import unittest
from envcrypto.crypto import *


class TestEnvcrypto(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_str = 'Fufu .$\x0f\r\ni^★地99'
        self.raw_bytes = b'ff\xf4YF7777777\x024\x66~\xa7\xb6\x5c12356'
        self.raw_list = ['A', '中', '', 1.23, True, {'x': (2, None)}]
        self.env_name = 'TEST_ENVCRYPTO'
        self.key = b'\02S\n\t@k\x02' * 100
        self.iv = 123

    def test_environ_str(self):
        env_value = set_environ(self.env_name, self.raw_str, self.key)
        self.assertIsInstance(env_value, str)
        self.assertIsNotNone(b58dc(env_value))

        get_env_value = get_environ(self.env_name)
        self.assertEqual(get_env_value, env_value)
        self.assertEqual(get_env_value, encrypt(self.raw_str, self.key))

        get_value = get_environ(self.env_name, self.key)
        self.assertIsInstance(get_value, str)
        self.assertEqual(get_value, self.raw_str)
        self.assertEqual(get_value, decrypt(get_env_value, self.key))

    def test_environ_bytes(self):
        env_value = set_environ(self.env_name, self.raw_bytes, self.key)
        self.assertIsInstance(env_value, str)
        self.assertIsNotNone(b58dc(env_value))

        get_env_value = get_environ(self.env_name)
        self.assertEqual(get_env_value, env_value)
        self.assertEqual(get_env_value, encrypt(self.raw_bytes, self.key))

        get_value = get_environ(self.env_name, self.key)
        self.assertIsInstance(get_value, bytes)
        self.assertEqual(get_value, self.raw_bytes)
        self.assertEqual(get_value, decrypt(get_env_value, self.key))

    def test_environ_other(self):
        env_value = set_environ(self.env_name, self.raw_list, self.key)
        self.assertIsInstance(env_value, str)
        self.assertIsNotNone(b58dc(env_value))

        get_env_value = get_environ(self.env_name)
        self.assertEqual(get_env_value, env_value)
        self.assertEqual(get_env_value, encrypt(self.raw_list, self.key))

        get_value = get_environ(self.env_name, self.key)
        self.assertIsInstance(get_value, str)
        self.assertEqual(get_value, str(self.raw_list))
        self.assertEqual(get_value, decrypt(get_env_value, self.key))

        env_value = set_environ(self.env_name, self.raw_list, key=None)
        self.assertEqual(env_value, str(self.raw_list))
        self.assertEqual(get_environ(self.env_name), str(self.raw_list))

    def test_helper(self):
        en_1 = encrypt_aes_cbc(self.raw_str, self.key)
        en_2 = encrypt_aes_cbc_hex(self.raw_str, self.key)
        en_3 = encrypt_aes_cbc_b58(self.raw_str, self.key)
        en_4 = encrypt_aes_cbc_b64(self.raw_str, self.key)
        en_5 = encrypt_aes_cbc_urlsafe_b64(self.raw_str, self.key)
        self.assertIsInstance(en_1, bytes)
        self.assertIsInstance(en_2, str)
        self.assertIsInstance(en_3, str)
        self.assertIsInstance(en_4, str)
        self.assertIsInstance(en_5, str)
        self.assertIsNotNone(en_1)
        self.assertIsNotNone(bytes.fromhex(en_2))
        self.assertIsNotNone(b58dc(en_3))
        self.assertIsNotNone(b64decode(en_4))
        self.assertIsNotNone(urlsafe_b64decode(en_5))
        de_1 = decrypt_aes_cbc(en_1, self.key)
        de_2 = decrypt_aes_cbc_hex(en_2, self.key)
        de_3 = decrypt_aes_cbc_b58(en_3, self.key)
        de_4 = decrypt_aes_cbc_b64(en_4, self.key)
        de_5 = decrypt_aes_cbc_urlsafe_b64(en_5, self.key)
        self.assertEqual(de_1, self.raw_str)
        self.assertEqual(de_2, self.raw_str)
        self.assertEqual(de_3, self.raw_str)
        self.assertEqual(de_4, self.raw_str)
        self.assertEqual(de_5, self.raw_str)

    def test_std_aes_cbc(self):
        for bits in [128, 192, 256]:
            aes = AESCipher(self.key, self.iv, bits=bits, style='pkcs7', with_type=False)
            en = aes.encrypt_aes_cbc(self.raw_bytes)
            en_helper = encrypt_aes_cbc(self.raw_bytes, self.key, self.iv, bits)
            self.assertEqual(en, en_helper[1:])
            de = aes.decrypt_aes_cbc(en)
            self.assertEqual(de, self.raw_bytes)
            self.assertEqual(de, decrypt_aes_cbc(en_helper, self.key, self.iv, bits))

    def test_other(self):
        key = False
        use_key = AESCipher(key).key
        use_iv = AESCipher(key).iv
        self.assertEqual(use_key, b'False\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b'
                                  b'\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b')
        self.assertEqual(use_key[:AES.block_size], use_iv)

        random_key = AESCipher().key
        self.assertEqual(len(random_key), 256 / 8)
        self.assertIsInstance(random_key, bytes)
        random_key = AESCipher(bits=128).key
        self.assertEqual(len(random_key), 128 / 8)
        self.assertIsInstance(random_key, bytes)
        random_key_100 = AESCipher().mk_key(length=100)
        self.assertEqual(len(random_key_100), 100)
        self.assertEqual(len(get_key_32()), 32)

        raw = True
        aes = AESCipher()
        res = aes.decrypt_aes_cbc(aes.encrypt_aes_cbc(raw))
        self.assertEqual(res, 'True')
        self.assertTrue(bool(res))

        tmp = TmpClass()
        res = decrypt_aes_cbc_b64(encrypt_aes_cbc_b64(tmp, self.key), self.key)
        self.assertEqual(res, 'I am TmpClass.')


class TmpClass:
    def __str__(self):
        return 'I am TmpClass.'


if __name__ == '__main__':
    unittest.main()
