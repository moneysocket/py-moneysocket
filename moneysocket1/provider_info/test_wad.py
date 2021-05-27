# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import os
import unittest
import json

from .wad import Wad

def load_json_file(path):
    f = open(path, "r")
    content = f.read()
    vectors = json.loads(content)
    f.close()
    return vectors

PATH = os.path.dirname(os.path.abspath(__file__))
ENCODE_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/03-wad-encode.json"))
DECODE_ERROR_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/03-wad-decode-error.json"))


class TestWad(unittest.TestCase):
    def test_wad_encode(self):
        for v in ENCODE_VECTORS:
            print("running: %s" % v['test_name'])
            w, err = Wad.from_dict(v['wad'])
            self.assertEqual(err, None)
            got_fmt = str(w)
            want_fmt = v['string_fmt']
            self.assertEqual(got_fmt, want_fmt)
            v_str = json.dumps(v['wad'], sort_keys=True, indent=1)
            got_str = w.to_json()
            self.assertEqual(v_str, got_str)

    def test_wad_decode_error(self):
        for v in DECODE_ERROR_VECTORS:
            print("running: %s" % v['test_name'])
            w, err = Wad.from_dict(v['input'])
            self.assertEqual(w, None)
            self.assertEqual(err, v['decode_error'])
