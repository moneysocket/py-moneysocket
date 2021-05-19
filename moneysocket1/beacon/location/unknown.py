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

    def to_dict(self):
        return {'type':  "Unknown",
                'bytes': self.byte_string.hex()}

    @staticmethod
    def parse_location(tlv):
        return UnknownLocation(tlv.t, tlv.v)

    def encode_tlv(self):
        return Tlv(self.type, self.byte_string).encode()
