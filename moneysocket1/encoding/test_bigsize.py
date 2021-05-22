# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import unittest
import random

from .convert import h2b
from .bigsize import BigSize



# From: https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#bigsize-decoding-tests

BIGSIZE_DECODING_TESTS = [
    {
        "name": "zero",
        "value": 0,
        "bytes": "00"
    },
    {
        "name": "one byte high",
        "value": 252,
        "bytes": "fc"
    },
    {
        "name": "two byte low",
        "value": 253,
        "bytes": "fd00fd"
    },
    {
        "name": "two byte high",
        "value": 65535,
        "bytes": "fdffff"
    },
    {
        "name": "four byte low",
        "value": 65536,
        "bytes": "fe00010000"
    },
    {
        "name": "four byte high",
        "value": 4294967295,
        "bytes": "feffffffff"
    },
    {
        "name": "eight byte low",
        "value": 4294967296,
        "bytes": "ff0000000100000000"
    },
    {
        "name": "eight byte high",
        "value": 18446744073709551615,
        "bytes": "ffffffffffffffffff"
    },
    {
        "name": "two byte not canonical",
        "value": 0,
        "bytes": "fd00fc",
        "exp_error": "decoded varint is not canonical"
    },
    {
        "name": "four byte not canonical",
        "value": 0,
        "bytes": "fe0000ffff",
        "exp_error": "decoded varint is not canonical"
    },
    {
        "name": "eight byte not canonical",
        "value": 0,
        "bytes": "ff00000000ffffffff",
        "exp_error": "decoded varint is not canonical"
    },
    {
        "name": "two byte short read",
        "value": 0,
        "bytes": "fd00",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "four byte short read",
        "value": 0,
        "bytes": "feffff",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "eight byte short read",
        "value": 0,
        "bytes": "ffffffffff",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "one byte no read",
        "value": 0,
        "bytes": "",
        "exp_error": "EOF"
    },
    {
        "name": "two byte no read",
        "value": 0,
        "bytes": "fd",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "four byte no read",
        "value": 0,
        "bytes": "fe",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "eight byte no read",
        "value": 0,
        "bytes": "ff",
        "exp_error": "unexpected EOF"
    }
]

FUZZ_TEST_ITERATIONS = 1000

class TestBigSize(unittest.TestCase):
    def test_decoding(self):
        for test in BIGSIZE_DECODING_TESTS:
            print("running: %s" % test['name'])
            v, remainder, err = BigSize.pop(h2b(test['bytes']))
            #print("%s %s %s %s" % (test['value'], str(v), remainder, err))
            if 'exp_error' in test.keys():
                self.assertNotEqual(err, None)
            else:
                self.assertEqual(v, test['value'])

    def test_small_fuzz(self):
        print("running: small fuzz")
        for _ in range(FUZZ_TEST_ITERATIONS):
            v = random.randint(0, 0xfc)
            encoded = BigSize.encode(v)
            decoded, remainder, err = BigSize.pop(encoded)
            self.assertEqual(err, None)
            self.assertEqual(len(remainder), 0)
            self.assertEqual(decoded, v)
        print("passed: small fuzz")

    def test_medium_fuzz(self):
        print("running: medium fuzz")
        for _ in range(FUZZ_TEST_ITERATIONS):
            v = random.randint(0, 0x1000)
            encoded = BigSize.encode(v)
            decoded, remainder, err = BigSize.pop(encoded)
            self.assertEqual(err, None)
            self.assertEqual(len(remainder), 0)
            self.assertEqual(decoded, v)
        print("passed: medium fuzz")

    def test_large_fuzz(self):
        print("running: large fuzz")
        for _ in range(FUZZ_TEST_ITERATIONS):
            v = random.randint(0, 0x10000000)
            encoded = BigSize.encode(v)
            decoded, remainder, err = BigSize.pop(encoded)
            self.assertEqual(err, None)
            self.assertEqual(len(remainder), 0)
            self.assertEqual(decoded, v)
        print("passed: large fuzz")

    def test_yuge_fuzz(self):
        print("running: yuge fuzz")
        for _ in range(FUZZ_TEST_ITERATIONS):
            v = random.randint(0, 0xffffffffffffffff)
            encoded = BigSize.encode(v)
            decoded, remainder, err = BigSize.pop(encoded)
            self.assertEqual(err, None)
            self.assertEqual(len(remainder), 0)
            self.assertEqual(decoded, v)
        print("passed: yuge fuzz")
