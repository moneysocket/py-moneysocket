# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import json
import traceback

from ..version import MoneysocketVersion
from ..encoding.tlv import Tlv
from ..encoding.bigsize import BigSize
from ..encoding.bech32 import Bech32
from ..encoding.namespace import Namespace

from .shared_seed import SharedSeed
from .location.websocket import WebsocketLocation
from .location.list import LocationList

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
    def __init__(self, hrp="moneysocket", version=None,
                 role_hint=None, shared_seed=None, locations=[],
                 unknown_tlvs=[]):
        if not role_hint is None:
            assert role_hint in ROLE_HINTS.values()
        assert hrp.startswith("moneysocket")
        self.hrp = hrp
        self.role_hint = role_hint
        self.shared_seed = shared_seed if shared_seed else SharedSeed()
        self.locations = locations
        self.unknown_tlvs = unknown_tlvs
        self.version = (version if version else
                        MoneysocketVersion.this_code_version())

    ###########################################################################

    def encode_bytes(self):
        generator_version_tlv = Tlv(GENERATOR_VERSION_TLV_TYPE,
                                    self.version.encode_bytes()).encode()
        if not self.role_hint is None:
            role_hint = bytes([self.role_hint])
            role_hint_tlv = Tlv(ROLE_HINT_TLV_TYPE, role_hint).encode()
        else:
            role_hint_tlv = b''
        hi, lo = self.shared_seed.get_hi_lo()
        hi_u64 = Namespace.encode_u64(hi)
        lo_u64 = Namespace.encode_u64(lo)
        shared_seed_tlv = Tlv(SHARED_SEED_TLV_TYPE, hi_u64 + lo_u64).encode()
        location_list_tlv = LocationList.encode_tlv(self.locations)
        unknown_tlvs = b''.join(t.encode() for t in self.unknown_tlvs)
        tlv_stream = (generator_version_tlv + role_hint_tlv + shared_seed_tlv +
                      location_list_tlv + unknown_tlvs)
        #print("generator version tlv: %s" % generator_version_tlv.hex())
        #print("role hint tlv:         %s" % role_hint_tlv.hex())
        #print("shared_seed tlv:       %s" % shared_seed_tlv.hex())
        #print("location list tlv:     %s" % location_list_tlv.hex())
        beacon_tlv = Tlv(BEACON_TLV_TYPE, tlv_stream)
        return beacon_tlv.encode()

    @staticmethod
    def decode_bytes(tlv_stream):
        #print(tlv_stream.hex())
        if not Namespace.tlvs_are_valid(tlv_stream):
            return None, None, None, None, None, "invalid beacon TLV"

        beacon_tlv, remainder, err = Tlv.pop(tlv_stream)
        if len(remainder) != 0:
            return None, None, None, None, None, "extra bytes in beacon"
        if beacon_tlv.t != BEACON_TLV_TYPE:
            return None, None, None, None, None, "unknown TLV"
        tlv_stream = beacon_tlv.v
        if not Namespace.tlvs_are_valid(tlv_stream):
            return None, None, None, None, None, "invalid TLVs in beacon"
        if len(tlv_stream) == 0:
            return None, None, None, None, None, "no TLVs"

        # Version TLV
        version_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
        # already validated TLV validity
        if version_tlv.t != GENERATOR_VERSION_TLV_TYPE:
            return None, None, None, None, None, "missing generator_version TLV"

        version, err = MoneysocketVersion.from_bytes(version_tlv.v)
        if err:
            return None, None, None, None, None, err

        if len(tlv_stream) == 0:
            return (None, None, None, None, None,
                    "missing shared_seed or role_hint TLV")
        ## optional role_hint TLV
        next_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
        # already validated TLV validity
        if next_tlv.t not in {ROLE_HINT_TLV_TYPE, SHARED_SEED_TLV_TYPE}:
            return None, None, None, None, None, "missing shared_seed TLV"
        if next_tlv.t == ROLE_HINT_TLV_TYPE:
            role_hint, role_hint_remainder, err = Namespace.pop_u8(next_tlv.v)
            if err:
                return (None, None, None, None, None,
                        "unable to parse role_hint")
            if role_hint not in ROLE_HINTS.values():
                return (None, None, None, None, None,
                        "unknown role_hint value")
            if len(role_hint_remainder) != 0:
                return (None, None, None, None, None,
                        "extra role_hint bytes")
            if len(tlv_stream) == 0:
                return (None, None, None, None, None,
                        "missing shared_seed TLV")
            shared_seed_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
            # already validated TLV validity
            if shared_seed_tlv.t != SHARED_SEED_TLV_TYPE:
                return None, None, None, None, None, "missing shared_seed TLV"
        else:
            role_hint = None
            shared_seed_tlv = next_tlv

        ## Shared seed TLV
        shared_seed_hi, shared_seed_hi_remainder, err = (
            Namespace.pop_u64(shared_seed_tlv.v))
        if err:
            return (None, None, None, None, None,
                    "unable to parse shared_seed_hi")
        shared_seed_lo, shared_seed_lo_remainder, err = (
            Namespace.pop_u64(shared_seed_hi_remainder))
        if err:
            return (None, None, None, None, None,
                    "unable to parse shared_seed_lo")
        if len(shared_seed_lo_remainder) != 0:
            return (None, None, None, None, None,
                    "extra shared_seed bytes")

        shared_seed = SharedSeed.from_hi_lo(shared_seed_hi, shared_seed_lo)

        if len(tlv_stream) == 0:
            return (None, None, None, None, None,
                    "missing location_list")
        # location list TLV
        location_list_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
        # already validated TLV validity
        locations, err = LocationList.parse_locations(location_list_tlv.v)
        if err:
            return None, None, None, None, None, err

        unknown_tlvs = [t for t in Namespace.iter_tlvs(tlv_stream)]
        return version, role_hint, shared_seed, locations, unknown_tlvs, None

    ###########################################################################

    def to_dict(self):
        role_hint = (ROLE_HINTS_STR[self.role_hint]
                     if not self.role_hint is None else None)
        v = self.version.to_dict()
        shared_seed = str(self.shared_seed)
        locations = [l.to_dict() for l in self.locations]
        unknown_tlvs = [t.to_dict() for t in self.unknown_tlvs]
        return {'hrp':               self.hrp,
                'role_hint':         role_hint,
                'generator_version': v,
                'shared_seed':       shared_seed,
                'locations':         locations,
                'unknown_tlvs':      unknown_tlvs,
               }

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True, indent=1)

    @staticmethod
    def from_dict(beacon_dict):
        # NOTE: this is not very strict and is not informative with errors
        try:
            hrp = beacon_dict['hrp']
            version = MoneysocketVersion.from_dict(
                beacon_dict['generator_version'])
            role_hint = (ROLE_HINTS[beacon_dict['role_hint']]
                         if not beacon_dict['role_hint'] is None else None)
            shared_seed = SharedSeed.from_hex_string(beacon_dict['shared_seed'])
            locations = LocationList.from_dict_list(beacon_dict['locations'])
            unknown_tlvs = [Tlv.from_dict(t) for t in
                            beacon_dict['unknown_tlvs']]

            beacon = Beacon(hrp=hrp, version=version, role_hint=role_hint,
                            shared_seed=shared_seed, locations=locations,
                            unknown_tlvs=unknown_tlvs)
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None, "dict interpration error"
        return beacon, None

    @staticmethod
    def from_json(beacon_json):
        try:
            beacon_dict = json.loads(beacon_json)
        except:
            return None, "json decode error"
        return Beacon.from_dict(beacon_dict)

    ###########################################################################

    def to_bech32(self):
        encoded_bytes = self.encode_bytes()
        return Bech32.encode_bytes(encoded_bytes, self.hrp)

    @staticmethod
    def from_bech32(beacon_str):
        try:
            hrp, tlv_stream = Bech32.decode_bytes(beacon_str)
        except Exception as e:
            #print(traceback.format_exc())
            #print(e)
            return None, "could not decode bech32 string"
        if not hrp or not tlv_stream:
            return None, "could not decode bech32 string"
        if not hrp.startswith('moneysocket'):
            return None, "unknown human readable part"

        version, role_hint, shared_seed, locations, unknown_tlvs, err = (
            Beacon.decode_bytes(tlv_stream))
        if err:
            return None, err
        b = Beacon(hrp=hrp, version=version, role_hint=role_hint,
                   shared_seed=shared_seed, locations=locations,
                   unknown_tlvs=unknown_tlvs)
        return b, None
