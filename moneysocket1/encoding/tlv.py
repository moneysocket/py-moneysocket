# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
from .convert import b2h
from .bigsize import BigSize

class Tlv:
    """
    For encoding/decoding values to/from TLV (Type-Length-Value) byte strings
    as defined in:
    https://github.com/lightningnetwork/lightning-rfc/blob/master/\
    01-messaging.md#type-length-value-format
    """
    def __init__(self, t, v):
        self.t = t
        self.l = len(v)
        self.v = v

    def __str__(self):
        return "(%d,%d,%s)" % (self.t, self.l, b2h(self.v))

    def to_dict(self):
        return {'t': self.t,
                'l': self.l,
                'v': self.v.hex()}

    @staticmethod
    def from_dict(tlv_dict):
        return Tlv(tlv_dict['t'], bytes.fromhex(tlv_dict['v']))

    ###########################################################################

    @staticmethod
    def peek(byte_string):
        t, remainder, err = BigSize.pop(byte_string)
        if err:
            return None, "could not get type: %s" % err
        l, remainder, err = BigSize.pop(remainder)
        if err:
            return None, "could not get length: %s" % err
        if len(remainder) < l:
            return None, "value truncated"
        return Tlv(t, remainder[:l]), None

    @staticmethod
    def pop(byte_string):
        t, byte_string, err = BigSize.pop(byte_string)
        if err:
            return None, None, "could not get type: %s" % err
        l, byte_string, err = BigSize.pop(byte_string)
        if err:
            return None, None, "could not get length: %s" % err
        if len(byte_string) < l:
            return None, None, "value truncated"
        return Tlv(t, byte_string[:l]), byte_string[l:], None

    ###########################################################################

    def encode(self):
        return BigSize.encode(self.t) + BigSize.encode(self.l) + self.v
