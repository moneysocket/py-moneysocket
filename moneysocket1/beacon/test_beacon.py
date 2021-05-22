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

DECODE_ERROR_VECTORS_JSON = """
[
    {
        "decode_error": "invalid beacon TLV",
        "input": {
            "beacon": "moneysocket1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv5mannja",
            "beacon_data_part_chunks": [
                "0032",
                "00030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e65"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "beacon one byte missing"
    },
    {
        "decode_error": "unknown TLV",
        "input": {
            "beacon": "moneysocket1nyeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usdwlwy7",
            "beacon_data_part_chunks": [
                "99",
                "3200030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "beacon TLV wrong type"
    },
    {
        "decode_error": "unknown human readable part",
        "input": {
            "beacon": "moneyysocket1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usmajtus",
            "beacon_data_part_chunks": [
                "003200030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneyysocket"
        },
        "test_name": "valid beacon with bad hrp"
    },
    {
        "decode_error": "could not decode bech32 string",
        "input": {
            "beacon": "lnbc1234560p1ps2s8ezpp5dequ583c7kpdhqvns8q55plfmy7zzx2kvnnsdjrq0l54pdajvfzqdpsd9h8vmmfvdjkvmmjd4hkuetewdhkx6m9w3jhxarkv43hgmmjxqyjw5qcqpjsp5lh9j2298qx5tmgdmkm66apl5azqtuqpd2jr6xg9phafs8tezruesrzjqt3cnkrp4nvadatspjvudsea63rq6mc79a4638glfumtap0uvrudwz07ecqq95gqqqqqqqlgqqqqqzsqyg9qy9qsqnt5975k4y9le5yn53c68hjt8sp20pm5w8ae300z9sxyp3u53s5uxsgdzkptreck7w0ulk7zfdza7zcs5mvz560wkfx3pjmnwptmzktcpf0acep",
            "beacon_data_part_chunks": null,
            "beacon_hrp": null
        },
        "test_name": "valid bech32 (bolt11)"
    },
    {
        "decode_error": "could not decode bech32 string",
        "input": {
            "beacon": "1qqeqqqcqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usukeesm",
            "beacon_data_part_chunks": [
                "003200030001020101020210a68bd6e9a77e3346c22063a3dec6678003160014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": ""
        },
        "test_name": "valid beacon with no hrp"
    },
    {
        "decode_error": "no TLVs",
        "input": {
            "beacon": "moneysocket1qqqqjvfdpq",
            "beacon_data_part_chunks": [
                "0000"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "no TLVs"
    },
    {
        "decode_error": "invalid TLVs in beacon",
        "input": {
            "beacon": "moneysocket1qqeqqpqqqypqzqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4us39k6nz",
            "beacon_data_part_chunks": [
                "0032",
                "0004000102",
                "010102",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "valid beacon TLV, invalid TLV in stream"
    },
    {
        "decode_error": "unable to decode version from bytes",
        "input": {
            "beacon": "moneysocket1qqesqpqqqyp2kqgpqgpppf5t6m56wl3ngmpzqcarmmrx0qqrzcqpgqgjwfjkccte9eek7cmtv46zumt0dejhjmw38a4",
            "beacon_data_part_chunks": [
                "0033",
                "0004000102ab",
                "010102",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "invalid generator_version value data"
    },
    {
        "decode_error": "missing generator_version TLV",
        "input": {
            "beacon": "moneysocket1qqkszqgzqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4us4fft6x",
            "beacon_data_part_chunks": [
                "002d",
                "",
                "010102",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "missing generator_version TLV"
    },
    {
        "decode_error": "missing shared_seed or role_hint TLV",
        "input": {
            "beacon": "moneysocket1qqzsqqcqqypq4jetf0",
            "beacon_data_part_chunks": [
                "0005",
                "0003000102",
                "",
                "",
                ""
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "missing shared_seed or role_hint TLV"
    },
    {
        "decode_error": "unknown role_hint value",
        "input": {
            "beacon": "moneysocket1qqeqqqcqqypqzq0lqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4uswx7p95",
            "beacon_data_part_chunks": [
                "0032",
                "0003000102",
                "0101ff",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "invalid role_hint value data (1)"
    },
    {
        "decode_error": "unable to parse role_hint",
        "input": {
            "beacon": "moneysocket1qqcsqqcqqypqzqqzzzngh4hf5alrx3kzyp368hkxv7qqx9sqzsq3yun9d3shjtnnda3kket59ekk7mn90yakj2xp",
            "beacon_data_part_chunks": [
                "0031",
                "0003000102",
                "0100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "invalid role_hint value data (2)"
    },
    {
        "decode_error": "extra role_hint bytes",
        "input": {
            "beacon": "moneysocket1qq6qqqcqqypqzqcqhmhsyy9x30twnfm7xdrvygrr500vveuqqvtqq9qpzfex2mrp0yh8xmmrddjhgtnddahx27gd3atdf",
            "beacon_data_part_chunks": [
                "0034",
                "0003000102",
                "010300beef",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "invalid role_hint value data (3)"
    },
    {
        "decode_error": "missing shared_seed TLV",
        "input": {
            "beacon": "moneysocket1qqsqqqcqqypqzqgqqvtqq9qpzfex2mrp0yh8xmmrddjhgtnddahx27gde68em",
            "beacon_data_part_chunks": [
                "0020",
                "0003000102",
                "010100",
                "",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "missing shared_seed TLV (1)"
    },
    {
        "decode_error": "missing shared_seed TLV",
        "input": {
            "beacon": "moneysocket1qqwsqqcqqypqx9sqzsq3yun9d3shjtnnda3kket59ekk7mn90y3z8zud",
            "beacon_data_part_chunks": [
                "001d",
                "0003000102",
                "",
                "",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "missing shared_seed TLV (no role_hint)"
    },
    {
        "decode_error": "missing shared_seed TLV",
        "input": {
            "beacon": "moneysocket1qqyqqqcqqypqzqgq3xa2d8",
            "beacon_data_part_chunks": [
                "0008",
                "0003000102",
                "010100",
                "",
                ""
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "missing shared_seed TLV (2)"
    },
    {
        "decode_error": "unable to parse shared_seed_hi",
        "input": {
            "beacon": "moneysocket1qq3sqqcqqypqzqgqqgq6vqckqq2qzynjv4kxz7fwwdhkx6m9wshx6mmwv4usepaq83",
            "beacon_data_part_chunks": [
                "0023",
                "0003000102",
                "010100",
                "0201a6",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "short shared_seed value (1)"
    },
    {
        "decode_error": "unable to parse shared_seed_lo",
        "input": {
            "beacon": "moneysocket1qqcsqqcqqypqzqgqqg86dz7kaxnhuv6xcgsx8g77censx9sqzsq3yun9d3shjtnnda3kket59ekk7mn90yj5qprp",
            "beacon_data_part_chunks": [
                "0031",
                "0003000102",
                "010100",
                "020fa68bd6e9a77e3346c22063a3dec667",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "short shared_seed value (2)"
    },
    {
        "decode_error": "extra shared_seed bytes",
        "input": {
            "beacon": "moneysocket1qqesqqcqqypqzqgqqgg6dz7kaxnhuv6xcgsx8g77cencpmsrzcqpgqgjwfjkccte9eek7cmtv46zumt0dejhjxjhzem",
            "beacon_data_part_chunks": [
                "0033",
                "0003000102",
                "010100",
                "0211a68bd6e9a77e3346c22063a3dec66780ee",
                "0316",
                "0014011272656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "long shared_seed value"
    },
    {
        "decode_error": "no locations in location_list",
        "input": {
            "beacon": "moneysocket1qqwqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcqfuxy55",
            "beacon_data_part_chunks": [
                "001c",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0300",
                ""
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "location_list empty"
    },
    {
        "decode_error": "invalid location_list",
        "input": {
            "beacon": "moneysocket1qqsqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcyllhdmnqnkjnx5",
            "beacon_data_part_chunks": [
                "0020",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0304",
                "ffeeddcc"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "location_list invalid TLVs"
    },
    {
        "decode_error": "no known locations in location_list",
        "input": {
            "beacon": "moneysocket1qqsqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcynyp2hngxcelly",
            "beacon_data_part_chunks": [
                "0020",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0304",
                "9902abcd"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "no known locations"
    },
    {
        "decode_error": "invalid websocket location TLVs",
        "input": {
            "beacon": "moneysocket1qqcsqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqc4qqfszynjv4kxz7fwwdhkx6m9wshx6mmwv59ctlda",
            "beacon_data_part_chunks": [
                "0031",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0315",
                "0013",
                "0112",
                "72656c61792e736f636b65742e6d6f6e65"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "invalid websocket location tlv_stream"
    },
    {
        "decode_error": "no websocket location TLVs",
        "input": {
            "beacon": "moneysocket1qq0qqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqczqqqqr9zec9",
            "beacon_data_part_chunks": [
                "001E",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0302",
                "0000",
                ""
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "empty websocket location tlv_stream"
    },
    {
        "decode_error": "unknown TLV",
        "input": {
            "beacon": "moneysocket1qqeqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqckqq2q7ynjv4kxz7fwwdhkx6m9wshx6mmwv4us32ywv2",
            "beacon_data_part_chunks": [
                "0032",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0316",
                "0014",
                "0f12",
                "72656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "unknown websocket location TLV (1)"
    },
    {
        "decode_error": "unknown TLV type",
        "input": {
            "beacon": "moneysocket1qq6qqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqccqqtqzynjv4kxz7fwwdhkx6m9wshx6mmwv4unxqq5unz5x",
            "beacon_data_part_chunks": [
                "0034",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0318",
                "0016",
                "0112",
                "72656c61792e736f636b65742e6d6f6e6579",
                "3300"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "unknown websocket location TLV (2)"
    },
    {
        "decode_error": "unable to parse generator_preference",
        "input": {
            "beacon": "moneysocket1qq6qqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqccqqtqqqqpzfex2mrp0yh8xmmrddjhgtnddahx27gzzsfzs",
            "beacon_data_part_chunks": [
                "0034",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0318",
                "0016",
                "0000",
                "0112",
                "72656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad generator_preference (1)"
    },
    {
        "decode_error": "extra generator_preference bytes",
        "input": {
            "beacon": "moneysocket1qqmqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqc6qqvqqq42hvq3yun9d3shjtnnda3kket59ekk7mn90yg7mfq5",
            "beacon_data_part_chunks": [
                "0036",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031a",
                "0018",
                "0002aabb",
                "0112",
                "72656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad generator_preference (2)"
    },
    {
        "decode_error": "generator_preference not minimally encoded",
        "input": {
            "beacon": "moneysocket1qq6sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqceqqtsqq0lqyf8yetvv9ujuum0vd4k2apwd4hkuete5l9v9q",
            "beacon_data_part_chunks": [
                "0035",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0319",
                "0017",
                "0001ff",
                "0112",
                "72656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad generator_preference (3)"
    },
    {
        "decode_error": "generator_preference not minimally encoded",
        "input": {
            "beacon": "moneysocket1qq6sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqceqqtsqq0lqyf8yetvv9ujuum0vd4k2apwd4hkuete5l9v9q",
            "beacon_data_part_chunks": [
                "0035",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0319",
                "0017",
                "0001ff",
                "0112",
                "72656c61792e736f636b65742e6d6f6e6579"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad generator_preference (3)"
    },
    {
        "decode_error": "missing hostname TLV",
        "input": {
            "beacon": "moneysocket1qqssqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqc9qqpsqqgqwld73w",
            "beacon_data_part_chunks": [
                "0021",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0305",
                "0003",
                "000100",
                ""
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with generator_preference missing hostname"
    },
    {
        "decode_error": "invalid hostname",
        "input": {
            "beacon": "moneysocket1qq6sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqceqqtsqqgqqyfqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyvj32k",
            "beacon_data_part_chunks": [
                "0035",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0319",
                "0017",
                "000100",
                "0112",
                "000000000000000000000000000000000000"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with invalid hostname"
    },
    {
        "decode_error": "error decoding hostname string",
        "input": {
            "beacon": "moneysocket1qq6sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqceqqtsqqgqqyf0llllllllllllllllllllllllllllhkcyuh",
            "beacon_data_part_chunks": [
                "0035",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0319",
                "0017",
                "000100",
                "0112",
                "ffffffffffffffffffffffffffffffffffff"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with invalid hostname unicode"
    },
    {
        "decode_error": "underrun while popping a u8",
        "input": {
            "beacon": "moneysocket1qq6qqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqccqqtqzynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqq2vjzjg",
            "beacon_data_part_chunks": [
                "0034",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0318",
                "0016",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "0200"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad use_tls (1)"
    },
    {
        "decode_error": "unknown use_tls setting",
        "input": {
            "beacon": "moneysocket1qq6sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqceqqtszynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqfndeqp7x",
            "beacon_data_part_chunks": [
                "0035",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0319",
                "0017",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "020133"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad use_tls (2)"
    },
    {
        "decode_error": "extra use_tls bytes",
        "input": {
            "beacon": "moneysocket1qqmqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqc6qqvqzynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqsqgswkwnlv",
            "beacon_data_part_chunks": [
                "0036",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031a",
                "0018",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "02020044"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad use_tls (3)"
    },
    {
        "decode_error": "use_tls not minimally encoded",
        "input": {
            "beacon": "moneysocket1qq6sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqceqqtszynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqgpyqxqn7",
            "beacon_data_part_chunks": [
                "0035",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0319",
                "0017",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "020101"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad use_tls (4)"
    },
    {
        "decode_error": "extra port bytes",
        "input": {
            "beacon": "moneysocket1qqusqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcaqqdszynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqgqqvpzyvclp4n9t",
            "beacon_data_part_chunks": [
                "0039",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031d",
                "001b",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "020100",
                "03022233"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad port (1)"
    },
    {
        "decode_error": "underrun while peeking a uint8",
        "input": {
            "beacon": "moneysocket1qqmsqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcmqqvszynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqgqqvqqfryxcx",
            "beacon_data_part_chunks": [
                "0037",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031b",
                "0019",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "020100",
                "0300"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad port (2)"
    },
    {
        "decode_error": "port value too large",
        "input": {
            "beacon": "moneysocket1qq7sqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqepqq0szynjv4kxz7fwwdhkx6m9wshx6mmwv4usxz0lllllllllllll7q8y2yx",
            "beacon_data_part_chunks": [
                "003D",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0321",
                "001f",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "0309ffffffffffffffffff"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad port (3)"
    },
    {
        "decode_error": "port not minimally encoded",
        "input": {
            "beacon": "moneysocket1qquqqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcuqqdqzynjv4kxz7fwwdhkx6m9wshx6mmwv4usyqgqqvq4qztrtze",
            "beacon_data_part_chunks": [
                "0038",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031c",
                "001a",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "020100",
                "030150"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad port (4)"
    },
    {
        "decode_error": "port not minimally encoded",
        "input": {
            "beacon": "moneysocket1qqmsqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcmqqvszynjv4kxz7fwwdhkx6m9wshx6mmwv4usxqlaqxas7hf6xv",
            "beacon_data_part_chunks": [
                "0037",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031b",
                "0019",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "0303fd01bb"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad port (5)"
    },
    {
        "decode_error": "path not minimally encoded",
        "input": {
            "beacon": "moneysocket1qq6qqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqccqqtqzynjv4kxz7fwwdhkx6m9wshx6mmwv4usgqqj59s6v",
            "beacon_data_part_chunks": [
                "0034",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "0318",
                "0016",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "0400"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad path (1)"
    },
    {
        "decode_error": "error decoding path",
        "input": {
            "beacon": "moneysocket1qqmsqqcqqypqzqgqqgg2dz7kaxnhuv6xcgsx8g77cencqqcmqqvszynjv4kxz7fwwdhkx6m9wshx6mmwv4usgqlllllsj2ev7n",
            "beacon_data_part_chunks": [
                "0037",
                "0003000102",
                "010100",
                "0210a68bd6e9a77e3346c22063a3dec66780",
                "031b",
                "0019",
                "011272656c61792e736f636b65742e6d6f6e6579",
                "0403ffffff"
            ],
            "beacon_hrp": "moneysocket"
        },
        "test_name": "websocket location with bad path (2)"
    }
]
"""

DECODE_ERROR_VECTORS = json.loads(DECODE_ERROR_VECTORS_JSON)

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
