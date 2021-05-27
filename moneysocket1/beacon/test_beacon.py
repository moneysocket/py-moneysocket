# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import os
import unittest
import json

from .beacon import Beacon
from .location.websocket import WebsocketLocation
from .location.unknown import UnknownLocation
from .beacon import ROLE_HINT_PROVIDER_GENERATOR_SEEKING_CONSUMER
from .beacon import ROLE_HINT_CONSUMER_GENERATOR_SEEKING_PROVIDER
from .beacon import ROLE_HINT_AUTOMATIC_GENERATOR
from ..encoding.bech32 import Bech32

def load_json_file(path):
    f = open(path, "r")
    content = f.read()
    vectors = json.loads(content)
    f.close()
    return vectors

PATH = os.path.dirname(os.path.abspath(__file__))
ENCODE_DECODE_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/02-beacon-encode-decode.json"))
DECODE_ERROR_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/02-beacon-decode-error.json"))


class TestBeaconEncode(unittest.TestCase):
    def test_encode_decode(self):
        self.maxDiff = None
        for test in ENCODE_DECODE_VECTORS:
            print("running: %s" % test["test_name"])
            input_bech32 = test['encoded']
            want_dict = test['decoded']
            want_json = json.dumps(want_dict, sort_keys=True, indent=1)
            want_beacon, err = Beacon.from_dict(want_dict)
            self.assertTrue(err is None)
            got_bech32 = want_beacon.to_bech32()
            self.assertEqual(input_bech32, got_bech32)
            got_beacon, err = Beacon.from_bech32(got_bech32)
            self.assertTrue(err is None)
            got_dict = got_beacon.to_dict()
            got_json = json.dumps(got_dict, sort_keys=True, indent=1)
            self.assertEqual(got_json, want_json)

    def test_decode_error(self):
        for test in DECODE_ERROR_VECTORS:
            print("running: %s" % test["test_name"])

            if test["input"]["beacon_data_part_chunks"]:
                data_part = b''.join(bytes.fromhex(chunk) for chunk in
                                     test["input"]["beacon_data_part_chunks"])
                #print("len: %d" % len(data_part))
                hrp = test["input"]['beacon_hrp']
                beacon = Bech32.encode_bytes(data_part, hrp)
                #print(beacon)
                self.assertEqual(beacon, test["input"]['beacon'])
            else:
                beacon = test["input"]['beacon']

            b, err = Beacon.from_bech32(beacon)
            self.assertNotEqual(err, None)
            self.assertEqual(b, None)
            self.assertEqual(err, test["decode_error"])
