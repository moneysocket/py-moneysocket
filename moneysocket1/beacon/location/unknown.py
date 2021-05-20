# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from ...encoding.tlv import Tlv

class UnknownLocation():
    def __init__(self, t, byte_string):
        self.type = t
        self.byte_string = byte_string

    def __str__(self):
        return "unknown: %d %s" % (self.type, self.byte_string.hex())

    ###########################################################################

    def to_dict(self):
        return {'location_type': "Unknown",
                'tlv_type':      self.type,
                'bytes':         self.byte_string.hex()}

    @staticmethod
    def from_dict(location_dict):
        byte_string = bytes.fromhex(location_dict['bytes'])
        return UnknownLocation(location_dict['tlv_type'], byte_string)

    ###########################################################################

    @staticmethod
    def parse_location(tlv):
        return UnknownLocation(tlv.t, tlv.v), None

    def encode_tlv(self):
        return Tlv(self.type, self.byte_string).encode()
