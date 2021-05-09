# -*- coding:utf-8 -*-
"""
    test_b58.py
    ~~~~~~~~

    :author: Fufu, 2021/5/8
"""
import sys
import unittest

from envcrypto.base58 import b58ec, b58dc, b58encode_int, b58encode


class TestB58(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_int = 1234567890
        self.raw_min_int = -1
        self.raw_str = 'Fufu .$\x0f\r\ni^★地99'
        self.raw_bytes = b'ff\xf4YF7777777\x024\x66~\xa7\xb6\x5c12356'
        self.raw_list = ['A', '中', '', 1.23, True, {'x': (2, None)}]

    def test_b58_int(self):
        ec = b58ec(self.raw_int)
        dc = b58dc(ec)
        self.assertEqual(ec[0], 'i')
        self.assertEqual(ec[1:], '2t6V2H')
        self.assertIsInstance(dc, int)
        self.assertEqual(dc, self.raw_int)

        self.assertEqual(b58dc(b58ec(True)), 1)
        self.assertEqual(b58dc(b58ec(False)), 0)
        self.assertEqual(b58dc(b58ec(0)), 0)

    def test_b58_bytes(self):
        ec = b58ec(self.raw_bytes)
        dc = b58dc(ec)
        self.assertEqual(ec[0], 'b')
        self.assertEqual(ec[1:], 'ALTFyFgfc4ZRwaVR3HN5sDUCg172N3iay')
        self.assertIsInstance(dc, bytes)
        self.assertEqual(dc, self.raw_bytes)

    def test_b58_str(self):
        ec = b58ec(self.raw_str)
        dc = b58dc(ec)
        self.assertEqual(ec[0], 's')
        self.assertEqual(ec[1:], 'yw8EiBQyqSoQD6jb5K6c3FzBrGG')
        self.assertIsInstance(dc, str)
        self.assertEqual(dc, self.raw_str)

    def test_b58_other(self):
        ec = b58ec(self.raw_list)
        dc = b58dc(ec)
        self.assertEqual(ec, b58ec(str(self.raw_list)))
        self.assertEqual(ec[0], 's')
        self.assertEqual(ec[1:], 'AxPAoHKWoXeh95n3PwtHKUXDzVS8bbwZ9RQhuwKoTfCzvSj3rj6WCFQzQKBznTW')
        self.assertIsInstance(dc, str)
        self.assertEqual(dc, str(self.raw_list))

        self.assertIsNone(b58dc('i***'))
        self.assertIsNone(b58dc('b***'))
        self.assertIsNone(b58dc('s***'))
        self.assertEqual(b58dc(b58ec(123.45)), '123.45')
        self.assertEqual(b58dc(b58ec(-1)), '-1')

    def test_b58_std(self):
        self.assertEqual(b58ec(123)[1:].encode('ascii'), b58encode_int(123))
        self.assertEqual(b58ec('Fufu')[1:].encode('ascii'), b58encode('Fufu'))
        self.assertEqual(b58ec(b'Fufu')[1:].encode('ascii'), b58encode(b'Fufu'))


if __name__ == '__main__':
    unittest.main()
