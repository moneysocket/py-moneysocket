# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import json

from ..moneysocket import VERSION_MAJOR
from ..moneysocket import VERSION_MINOR
from ..moneysocket import VERSION_PATCH
from ..encoding.tlv import Tlv
from ..encoding.bigsize import BigSize
from ..encoding.bech32 import Bech32
from ..encoding.namespace import Namespace

from .shared_seed import SharedSeed
from .location.websocket import WebsocketLocation

BEACON_TLV_TYPE = 0
GENERATOR_VERSION_TLV_TYPE = 0
ROLE_HINT_TLV_TYPE = 1
SHARED_SEED_TLV_TYPE = 2
LOCATION_LIST_TLV_TYPE = 3

ROLE_HINT_PROVIDER_GENERATOR_SEEKING_CONSUMER = 0x0
ROLE_HINT_CONSUMER_GENERATOR_SEEKING_PROVIDER = 0x1
ROLE_HINT_AUTOMATIC_GENERATOR = 0x2

ROLE_HINTS = {
    "PROVIDER_GENERATOR_SEEKING_CONSUMER":
        ROLE_HINT_PROVIDER_GENERATOR_SEEKING_CONSUMER,
    "CONSUMER_GENERATOR_SEEKING_PROVIDER":
        ROLE_HINT_CONSUMER_GENERATOR_SEEKING_PROVIDER,
    "AUTOMATIC_GENERATOR":
        ROLE_HINT_AUTOMATIC_GENERATOR,
}

ROLE_HINTS_STR = {v:k for k, v in ROLE_HINTS.items()}

class Beacon():
    def __init__(self, hrp="moneysocket", version_major=VERSION_MAJOR,
                 version_minor=VERSION_MINOR, version_patch=VERSION_PATCH,
                 role_hint=None, shared_seed=None, locations=[]):
        if role_hint:
            assert role_hint in ROLE_HINTS.values()
        assert hrp.startswith("moneysocket")
        self.hrp = hrp
        self.role_hint = role_hint
        self.shared_seed = shared_seed if shared_seed else SharedSeed()
        self.locations = []
        self.version_major = version_major
        self.version_minor = version_minor
        self.version_patch = version_patch

    ###########################################################################

    def encode_bytes(self):
        generator_version = bytes([self.version_major, self.version_minor,
                                   self.version_patch])
        generator_version_tlv = Tlv(GENERATOR_VERSION_TLV_TYPE,
                                    generator_version).encode()

        if self.role_hint:
            role_hint = bytes([self.role_hint])
            role_hint_tlv = Tlv(ROLE_HINT_TLV_TYPE, role_hint).encode()
        else:
            role_hint_tlv = b''

        hi, lo = self.shared_seed.get_hi_lo()
        hi_u64 = Namespace.encode_u64(hi)
        lo_u64 = Namespace.encode_u64(lo)
        shared_seed_tlv = Tlv(SHARED_SEED_TLV_TYPE, hi_u64 + lo_u64).encode()

        tlv_stream = generator_version_tlv + role_hint_tlv + shared_seed_tlv
        beacon_tlv = Tlv(BEACON_TLV_TYPE, tlv_stream)
        return beacon_tlv.encode()

    def decode_bytes(self, data_part):
        beacon_tlv, remainder, err = Tlv.pop(data_part)
        if len(remainder) != 0:
            return None, None, None, None, None, None, "extra bytes in beacon"
        tlv_stream = beacon_tlv.v
        version_tlv, tlv_stream, err = Tlv.pop(tlv_stream)
        if err:
            return None, None, None, None, None, None, err

        version_major, version_remainder, err = Namespace.pop_u8(version_tlv)
        if err:
            return None, None, None, None, None, None, err
        version_minor, version_remainder, err = (
            Namespace.pop_u8(version_remainder))
        if err:
            return None, None, None, None, None, None, err
        version_patch, version_remainder, err = (
            Namespace.pop_u8(version_remainder))
        if err:
            return None, None, None, None, None, None, err
        if len(version_remainder) != 0:
            return (None, None, None, None, None, None,
                    "extra generator_version bytes")

        return version_major, version_minor, version_patch, None, None, None, None

    ###########################################################################

    def to_json(self):
        role_hint = ROLE_HINTS_STR[self.role_hint] if self.role_hint else None
        v = {'major': self.version_major,
             'minor': self.version_minor,
             'patch': self.version_patch}
        shared_seed = str(self.shared_seed)
        b = {'hrp':               self.hrp,
             'role_hint':         role_hint,
             'generator_version': v,
             'shared_seed':       shared_seed
            }
        return json.dumps(b, sort_keys=True, indent=1)

    def to_bech32(self):
        encoded_bytes = self.encode_bytes()
        return Bech32.encode_bytes(encoded_bytes, self.hrp)

    @staticmethod
    def from_bech32(beacon_str):
        try:
            print("beacon_str: %s" % beacon_str)
            hrp, decoded_bytes = Bech32.decode_bytes(beacon_str)
        except Exception as e:
            print(e)
            return None, "could not decode bech32 string"
        if not hrp or not decoded_bytes:
            print(hrp)
            return None, "could not decode bech32 string"
        if not hrp.startswith('moneysocket'):
            return None, "unknown human readable part"

        (version_major, version_minor, version_patch, role_hint, shared_seed,
         locations, err) = Beacon.decode_bytes(decoded_bytes)
        if err:
            return None, err
        b = Beacon(hrp=hrp, version_major=version_major,
                   version_minor=version_minor,
                   version_patch=version_patch, role_hint=role_hint,
                   shared_seed=shared_seed, locations=locations)
        return b, None
