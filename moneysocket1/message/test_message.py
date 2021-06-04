# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import os
import unittest
import json

from .message import Message

def load_json_file(path):
    f = open(path, "r")
    content = f.read()
    vectors = json.loads(content)
    f.close()
    return vectors

PATH = os.path.dirname(os.path.abspath(__file__))
ENCODE_DECODE_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/04-message-encode-decode.json"))



class TestMessage(unittest.TestCase):
    def xxx_test_message_encode_decode(self):
        for v in ENCODE_DECODE_VECTORS:
            print("running: %s" % v["test_name"])
            input_bin = bytes.fromhex(v['encoded'])
            input_dict = v['decoded']
            want_json = json.dumps(input_dict, sort_keys=True, indent=1)

            got_message, err = Message.decode_tlv(input_bin)
            print(err)
            self.assertTrue(err is None)

            got_dict = got_message.to_dict()
            got_json = json.dumps(got_dict, sort_keys=True, indent=1)
            self.assertEqual(got_json, want_json)


    def xxx_test_message_encode_decode(self):
        for v in ENCODE_DECODE_VECTORS:
            print("running: %s" % v["test_name"])
            input_bin = bytes.fromhex(v['encoded'])
            input_dict = v['decoded']
            m = Message.from_dict(input_dict)
            b = m.encode_bytes()
            print(b.hex())

            got_message, err = Message.decode_bytes(input_bin)
            print(err)
            self.assertTrue(err is None)

            got_dict = got_message.to_dict()
            got_json = json.dumps(got_dict, sort_keys=True, indent=1)
            self.assertEqual(got_json, want_json)
