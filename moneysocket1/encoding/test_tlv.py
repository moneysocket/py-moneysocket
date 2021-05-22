# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import unittest

from .convert import h2b
from .tlv import Tlv


# from: https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#tlv-decoding-successes
TLV_VALID_TESTS = [
     {'stream': "2100",
      't':      0x21,
      'l':      0,
      'v':      "",
      'r':      ""},
     {'stream': "fd020100",
      't':      0x201,
      'l':      0,
      'v':      "",
      'r':      ""},
     {'stream': "fd00fd00",
      't':      0xfd,
      'l':      0,
      'v':      "",
      'r':      ""},
     {'stream': "fd00ff00",
      't':      0xff,
      'l':      0,
      'v':      "",
      'r':      ""},
     {'stream': "fe0200000100",
      't':      0x2000001,
      'l':      0,
      'v':      "",
      'r':      ""},
     {'stream': "ff020000000000000100",
      't':      0x200000000000001,
      'l':      0,
      'v':      "",
      'r':      ""},
]


# from: https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#tlv-decoding-failures
TLV_INVALID_TESTS = [
     {'stream': ""}, # empty byte stream is counted as invalid by this lib
     {'stream': "fd"},
     {'stream': "fd01"},
     {'stream': "fd000100"},
     {'stream': "fd0101"},
     {'stream': "0ffd26"},
     {'stream': "0ffd2602"},
     {'stream': "0ffd000100"},
     {'stream': "0ffd0201000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
]

class TestTlv(unittest.TestCase):
    def test_valid(self):
        print("running: valid tlv encoding cases")
        for test in TLV_VALID_TESTS:
            peek_tlv, peek_err = Tlv.peek(h2b(test['stream']))
            pop_tlv, remainder, pop_err = Tlv.pop(h2b(test['stream']))

            self.assertEqual(peek_err, None)
            self.assertEqual(peek_tlv.t, test['t'])
            self.assertEqual(peek_tlv.l, test['l'])
            self.assertEqual(peek_tlv.v, h2b(test['v']))

            self.assertEqual(pop_err, None)
            self.assertEqual(pop_tlv.t, test['t'])
            self.assertEqual(pop_tlv.l, test['l'])
            self.assertEqual(pop_tlv.v, h2b(test['v']))
            self.assertEqual(remainder, h2b(test['r']))
        print("done running: valid tlv encoding cases")

    def test_invalid(self):
        print("running: invalid tlv decoding cases")
        for test in TLV_INVALID_TESTS:
            peek_tlv, peek_err = Tlv.peek(h2b(test['stream']))
            pop_tlv, remainder, pop_err = Tlv.pop(h2b(test['stream']))
            self.assertNotEqual(peek_err, None)
            self.assertNotEqual(pop_err, None)
        print("done running: invalid tlv decoding cases")


