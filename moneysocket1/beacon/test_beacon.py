# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import unittest
import json

from .beacon import Beacon
from .location.websocket import WebsocketLocation
from .location.unknown import UnknownLocation
from .beacon import ROLE_HINT_PROVIDER_GENERATOR_SEEKING_CONSUMER
from .beacon import ROLE_HINT_CONSUMER_GENERATOR_SEEKING_PROVIDER
from .beacon import ROLE_HINT_AUTOMATIC_GENERATOR


ENCODE_DECODE_VECTORS = [
{
    'test_name': 'typical basic beacon',
    'encoded': "moneysocket1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usecdqd7",
    'decoded': {
         "generator_version": {
          "major": 0,
          "minor": 1,
          "patch": 2
         },
        "hrp": "moneysocket",
        "locations": [
            {"generator_preference": 255,
             "hostname": "relay.socket.money",
             "location_type": "WebSocket",
              "path": "",
              "port": 443,
              "use_tls": True
            },
        ],
        "role_hint": "AUTOMATIC_GENERATOR",
        "shared_seed": "a68bd6e9a77e3346c22063a3dec66780",
        "unknown_tlvs": []
    },
},
{
    'test_name': 'two websocket locations',
    'encoded': "moneysocket1qpgsqqcpqgpszqgpqgg2dz7kaxnhuv6xcgsx8g77cencqqe4qqtsqqgzqyf8yetvv9ujuum0vd4k2apwd4hkueteqqdqqqgpqyykcmmrv9kxsmmnwspqzqqrq073lyqyqfmhx74kf6m",
    'decoded': {
         "generator_version": {
          "major": 1,
          "minor": 2,
          "patch": 3
         },
        "hrp": "moneysocket",
        "locations": [
            {"generator_preference": 2,
             "hostname": "relay.socket.money",
             "location_type": "WebSocket",
              "path": "",
              "port": 443,
              "use_tls": True
            },
            {"generator_preference": 1,
             "hostname": "localhost",
             "location_type": "WebSocket",
              "path": "ws",
              "port": 8080,
              "use_tls": False
            },
        ],
        "role_hint": "CONSUMER_GENERATOR_SEEKING_PROVIDER",
        "shared_seed": "a68bd6e9a77e3346c22063a3dec66780",
        "unknown_tlvs": []
    },
},
]

DECODE_ERROR_VECTORS = [
{
    'encoded': {
    },
    'error': {
    }
},

]

class TestBeaconEncode(unittest.TestCase):
    def xxx_test_boof(self):
        locations = [WebsocketLocation("relay.socket.money"),
                     UnknownLocation(1234, b'abc123')]
        b = Beacon(role_hint=ROLE_HINT_AUTOMATIC_GENERATOR, locations=locations)
        b1_32 = b.to_bech32()
        print(b1_32)
        b1_j = b.to_json()
        print(b1_j)
        b2, err = Beacon.from_bech32(b1_32)
        print(err)
        print(b2.to_json())

    def test_encode_decode(self):
        self.maxDiff = None
        for test in ENCODE_DECODE_VECTORS:
            print("running: %s" % test['test_name'])
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
