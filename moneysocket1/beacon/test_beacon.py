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
from ..encoding.bech32 import Bech32

ENCODE_DECODE_VECTORS_JSON = """
[
    {
        "decoded": {
            "generator_version": {
                "major": 0,
                "minor": 1,
                "patch": 2
            },
            "hrp": "moneysocket",
            "locations": [
                {
                    "generator_preference": 255,
                    "hostname": "relay.socket.money",
                    "location_type": "WebSocket",
                    "path": "",
                    "port": 443,
                    "use_tls": true
                }
            ],
            "role_hint": "AUTOMATIC_GENERATOR",
            "shared_seed": "a68bd6e9a77e3346c22063a3dec66780",
            "unknown_tlvs": []
        },
        "encoded": "moneysocket1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usecdqd7",
        "test_name": "typical basic beacon"
    },
    {
        "decoded": {
            "generator_version": {
                "major": 0,
                "minor": 1,
                "patch": 2
            },
            "hrp": "moneysocket-paste-into-wallet-",
            "locations": [
                {
                    "generator_preference": 255,
                    "hostname": "relay.socket.money",
                    "location_type": "WebSocket",
                    "path": "",
                    "port": 443,
                    "use_tls": true
                }
            ],
            "role_hint": null,
            "shared_seed": "a68bd6e9a77e3346c22063a3dec66780",
            "unknown_tlvs": []
        },
        "encoded": "moneysocket-paste-into-wallet-1qqhsqqcqqypqyy9x30twnfm7xdrvygrr500vveuqqvtqq9qpzfex2mrp0yh8xmmrddjhgtnddahx27g6jrd6q",
        "test_name": "extended hrp no role hintng"
    },
    {
        "decoded": {
            "generator_version": {
                "major": 1,
                "minor": 2,
                "patch": 3
            },
            "hrp": "moneysocket",
            "locations": [
                {
                    "generator_preference": 2,
                    "hostname": "relay.socket.money",
                    "location_type": "WebSocket",
                    "path": "",
                    "port": 443,
                    "use_tls": true
                },
                {
                    "generator_preference": 1,
                    "hostname": "localhost",
                    "location_type": "WebSocket",
                    "path": "ws",
                    "port": 8080,
                    "use_tls": false
                }
            ],
            "role_hint": "CONSUMER_GENERATOR_SEEKING_PROVIDER",
            "shared_seed": "a68bd6e9a77e3346c22063a3dec66780",
            "unknown_tlvs": []
        },
        "encoded": "moneysocket1qpgsqqcpqgpszqgpqgg2dz7kaxnhuv6xcgsx8g77cencqqe4qqtsqqgzqyf8yetvv9ujuum0vd4k2apwd4hkueteqqdqqqgpqyykcmmrv9kxsmmnwspqzqqrq073lyqyqfmhx74kf6m",
        "test_name": "two websocket locations"
    },
    {
        "decoded": {
            "generator_version": {
                "major": 3,
                "minor": 2,
                "patch": 1
            },
            "hrp": "moneysocket",
            "locations": [
                {
                    "generator_preference": 2,
                    "hostname": "relay.socket.money",
                    "location_type": "WebSocket",
                    "path": "",
                    "port": 443,
                    "use_tls": true
                },
                {
                    "bytes": "616263313233",
                    "location_type": "Unknown",
                    "tlv_type": 1234
                },
                {
                    "bytes": "deadbeef",
                    "location_type": "Unknown",
                    "tlv_type": 4321
                }
            ],
            "role_hint": "PROVIDER_GENERATOR_SEEKING_CONSUMER",
            "shared_seed": "a68bd6e9a77e3346c22063a3dec66780",
            "unknown_tlvs": [
                {
                    "l": 3,
                    "t": 123,
                    "v": "abcdef"
                },
                {
                    "l": 6,
                    "t": 444,
                    "v": "deadbeefdead"
                }
            ]
        },
        "encoded": "moneysocket1qptqqqcrqgqszqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqetqqtsqqgzqyf8yetvv9ujuum0vd4k2apwd4hkuetel5zdypnpvf3nzv3nl5gwzpx74klw77cr40x7llgphsrdatd7al026va5fde",
        "test_name": "unknown locations unknown tlvs"
    }
]
"""

ENCODE_DECODE_VECTORS = json.loads(ENCODE_DECODE_VECTORS_JSON)

DECODE_ERROR_VECTORS = [
{
    "test_name": "beacon one byte missing",
    "input": {
        "beacon_data_part_chunks": [
            "0032", # beacon TL
            "00030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e65" # beacon V (last byte missing)
        ],
        'beacon_hrp': "moneysocket",
        'beacon': "moneysocket1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv5mannja"
    },
    "decode_error": "invalid beacon TLV"
},
{
    "test_name": "beacon TLV wrong type",
    "input": {
        "beacon_data_part_chunks": [
            "99", # beacon T (wrong)
            "3200030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e6579" # beacon LV
        ],
        'beacon_hrp': "moneysocket",
        'beacon': "moneysocket1nyeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usdwlwy7"
    },
    "decode_error": "unknown TLV"
},
{
    "test_name": "valid beacon with bad hrp",
    "input": {
        "beacon_data_part_chunks": [
            "003200030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e6579"
        ],
        'beacon_hrp': "moneyysocket",
        'beacon': "moneyysocket1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usmajtus"
    },
    "decode_error": "unknown human readable part"
},
{
    "test_name": "valid bech32 (bolt11)",
    "input": {
        "beacon_data_part_chunks": None,
        'beacon_hrp': None,
        'beacon': "lnbc1234560p1ps2s8ezpp5dequ583c7kpdhqvns8q55plfmy7zzx2kvnnsdjrq0l54pdajvfzqdpsd9h8vmmfvdjkvmmjd4hkuetewdhkx6m9w3jhxarkv43hgmmjxqyjw5qcqpjsp5lh9j2298qx5tmgdmkm66apl5azqtuqpd2jr6xg9phafs8tezruesrzjqt3cnkrp4nvadatspjvudsea63rq6mc79a4638glfumtap0uvrudwz07ecqq95gqqqqqqqlgqqqqqzsqyg9qy9qsqnt5975k4y9le5yn53c68hjt8sp20pm5w8ae300z9sxyp3u53s5uxsgdzkptreck7w0ulk7zfdza7zcs5mvz560wkfx3pjmnwptmzktcpf0acep",
    },
    "decode_error": "could not decode bech32 string"
},
{
    "test_name": "valid beacon with no hrp",
    "input": {
        "beacon_data_part_chunks": [
            "003200030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e6579"
        ],
        'beacon_hrp': "",
        'beacon': "1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usukeesm"
    },
    "decode_error": "could not decode bech32 string"
},
{
    "test_name": "valid beacon TLV, invalid TLV in stream",
    "input": {
        "beacon_data_part_chunks": [
            "0032", # beacon TL
            "0004000102", # generator_version TLV (wrong L)
            "010102", # role hint TLV
            "0210a68bd6e9a77e3346c22063a3dec66780", # shared_seed TLV
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqeqqpqqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4us39k6nz"
    },
    "decode_error": "invalid TLVs in beacon"
},
{
    "test_name": "invalid generator_version value data",
    "input": {
        "beacon_data_part_chunks": [
            "0033", # beacon TL
            "0004000102ab", # generator_version TLV (extra byte)
            "010102", # role_hint TLV
            "0210a68bd6e9a77e3346c22063a3dec66780", # shared_seed TLV
            "0316" # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqesqpqqqyp2kqgpqgpppf5t6m56wl3ngmpzqcarmmrx0qqrzcqpgqgjwfjkccte9eek7cmtv46zumt0dejhjmw38a4"
    },
    "decode_error": "unable to decode version from bytes"
},
{
    "test_name": "missing generator_version TLV",
    "input": {
        "beacon_data_part_chunks": [
            "002d", # beacon TL
            "", # generator_version TLV (missing)
            "010102" # role hint TLV
            "0210a68bd6e9a77e3346c22063a3dec66780", # shared_seed TLV
            "0316" # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqkszqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4us4fft6x"
    },
    "decode_error": "missing generator_version TLV"
},
{
    "test_name": "invalid role_hint value data (1)",
    "input": {
        "beacon_data_part_chunks": [
            "0032", # beacon TL
            "0003000102", # generator_version TLV
            "0101ff" # role_hint TLV (bad value)
            "0210a68bd6e9a77e3346c22063a3dec66780", # shared_seed TLV
            "0316" # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqeqqqcqqypqzq0lqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4uswx7p95"
    },
    "decode_error": "unknown role_hint value"
},
{
    "test_name": "invalid role_hint value data (2)",
    "input": {
        "beacon_data_part_chunks": [
            "0031", # beacon TL
            "0003000102", # generator_version TLV
            "0100" # role_hint TLV (no value)
            "0210a68bd6e9a77e3346c22063a3dec66780", # shared_seed TLV
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqcsqqcqqypqzqqzzzngh4hf5alrx3kzyp368hkxv7qqx9sqzsq3yun9d3shjtnnda3kket59ekk7mn90yakj2xp"
    },
    "decode_error": "unable to parse role_hint"
},
{
    "test_name": "invalid role_hint value data (3)",
    "input": {
        "beacon_data_part_chunks": [
            "0034", # beacon TL
            "0003000102", # generator_version TLV
            "010300beef", # role_hint TLV (extra bytes)
            "0210a68bd6e9a77e3346c22063a3dec66780", # shared_seed TLV
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qq6qqqcqqypqzqcqhmhsyy9x30twnfm7xdrvygrr500vveuqqvtqq9qpzfex2mrp0yh8xmmrddjhgtnddahx27gd3atdf"
    },
    "decode_error": "extra role_hint bytes"
},
{
    "test_name": "missing shared_seed TLV",
    "input": {
        "beacon_data_part_chunks": [
            "0020", # beacon TL
            "0003000102", # generator_version TLV
            "010100", # role_hint TLV
            "", # shared_seed TLV (missing)
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqsqqqcqqypqzqgqqvtqq9qpzfex2mrp0yh8xmmrddjhgtnddahx27gde68em"
    },
    "decode_error": "missing shared_seed TLV"
},
{
    "test_name": "missing shared_seed TLV (no role_hint)",
    "input": {
        "beacon_data_part_chunks": [
            "001d", # beacon TL
            "0003000102", # generator_version TLV
            "", # role_hint TLV (none)
            "", # shared_seed TLV (missing)
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqwsqqcqqypqx9sqzsq3yun9d3shjtnnda3kket59ekk7mn90y3z8zud"
    },
    "decode_error": "missing shared_seed TLV"
},
{
    "test_name": "short shared_seed value (1)",
    "input": {
        "beacon_data_part_chunks": [
            "0023", # beacon TL
            "0003000102", # generator_version TLV
            "010100", # role_hint TLV
            "0201a6", # shared_seed TLV (less than hi u64)
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qq3sqqcqqypqzqgqqgq6vqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usepaq83"
    },
    "decode_error": "unable to parse shared_seed_hi"
},
{
    "test_name": "short shared_seed value (2)",
    "input": {
        "beacon_data_part_chunks": [
            "0031", # beacon TL
            "0003000102", # generator_version TLV
            "010100", # role_hint TLV
            "020fa68bd6e9a77e3346c22063a3dec667", # shared_seed TLV (less than full lo u64)
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqcsqqcqqypqzqgqqg86dz7kaxnhuv6xcgsx8g77censx9sqzsq3yun9d3shjtnnda3kket59ekk7mn90yj5qprp"
    },
    "decode_error": "unable to parse shared_seed_lo"
},
{
    "test_name": "long shared_seed value (2)",
    "input": {
        "beacon_data_part_chunks": [
            "0033", # beacon TL
            "0003000102", # generator_version TLV
            "010100", # role_hint TLV
            "0211a68bd6e9a77e3346c22063a3dec66780ee", # shared_seed TLV (extra byte)
            "0316", # location_list TL
            "0014011272656c61792e736f636b65742e6d6f6e6579" # location_list V
        ],
        "beacon_hrp": "moneysocket",
        "beacon": "moneysocket1qqesqqcqqypqzqgqqgg6dz7kaxnhuv6xcgsx8g77cencpmsrzcqpgqgjwfjkccte9eek7cmtv46zumt0dejhjxjhzem"
    },
    "decode_error": "extra shared_seed bytes"
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

    def xxx_test_encode_decode(self):
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
