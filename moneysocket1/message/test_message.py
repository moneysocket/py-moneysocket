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

DECODE_ERROR_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/04-message-decode-error.json"))



class TestMessage(unittest.TestCase):
    def test_message_encode_decode(self):
        for v in ENCODE_DECODE_VECTORS:
            input_dict = v['decoded']
            m = Message.from_dict(input_dict)
            b = m.encode_bytes()
            print("bytes from dict: %s" % b.hex())


            print("running: %s" % v["test_name"])
            input_bin = bytes.fromhex(v['encoded'])
            decoded_message, err = Message.decode_bytes(input_bin)
            print(err)
            self.assertTrue(err is None)


            want_dict = v['decoded']
            want_message = Message.from_dict(input_dict)

            decoded_json = json.dumps(decoded_message.to_dict(),
                                      sort_keys=True, indent=1)
            want_json = json.dumps(want_message.to_dict(), sort_keys=True,
                                   indent=1)
            self.assertEqual(decoded_json, want_json)

            encoded1 = decoded_message.encode_bytes()
            encoded2 = want_message.encode_bytes()
            self.assertEqual(encoded1, encoded2)
            self.assertEqual(encoded1, input_bin)

    def test_message_decode_error(self):
        for v in DECODE_ERROR_VECTORS:
            print("running: %s" % v["test_name"])
            b = b''
            for chunk in v['input_chunks']:
                if type(chunk) == str:
                    b += bytes.fromhex(chunk)
                elif type(chunk) == dict:
                    print("chunk: %s" % chunk)
                    d = json.dumps(chunk).encode("utf8")
                    print("encoded: %s" % d.hex())
                    print("encodesize: %x" % len(d))
                    b += d
                    print("tlv size: %x" % (len(b) - 2))
            print("decoding: %s" % b.hex())
            m, err = Message.decode_bytes(b)
            self.assertEqual(m, None)
            self.assertEqual(err, v['decode_error'])
