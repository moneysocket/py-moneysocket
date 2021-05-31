# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import os
import unittest
import json

from .provider_info import ProviderInfo

def load_json_file(path):
    f = open(path, "r")
    content = f.read()
    vectors = json.loads(content)
    f.close()
    return vectors

PATH = os.path.dirname(os.path.abspath(__file__))
ENCODE_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/03-provider-info-encode.json"))
DECODE_ERROR_VECTORS = load_json_file(
    os.path.join(PATH, "../../test_vectors/03-provider-info-decode-error.json"))

class TestProviderInfo(unittest.TestCase):
    def test_provider_info_encode(self):
        for v in ENCODE_VECTORS:
            print("running: %s" % v['test_name'])
            provider_info, err = ProviderInfo.from_dict(v['provider_info'])
            self.assertEqual(err, None)
            v_str = json.dumps(v['provider_info'], sort_keys=True, indent=1)
            got_str = provider_info.to_json()
            self.assertEqual(v_str, got_str)

    def test_provider_info_decode_err(self):
        for v in DECODE_ERROR_VECTORS:
            print("running: %s" % v['test_name'])
            provider_info, err = ProviderInfo.from_dict(v['input'])
            self.assertEqual(provider_info, None)
            self.assertEqual(err, v['decode_error'])
