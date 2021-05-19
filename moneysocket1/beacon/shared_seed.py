# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import os
import hashlib

class SharedSeed():
    SHARED_SEED_LEN = 16

    def __init__(self, seed_bytes=None):
        self.seed_bytes = (seed_bytes if seed_bytes is not None else
                           os.urandom(SharedSeed.SHARED_SEED_LEN))
        assert len(self.seed_bytes) == SharedSeed.SHARED_SEED_LEN

    def __hash__(self):
        return int.from_bytes(self.seed_bytes, byteorder='big')

    def __eq__(self, other):
        if not other:
            return False
        return self.seed_bytes == other.seed_bytes

    @staticmethod
    def from_hex_string(hex_str):
        if len(hex_str) != SharedSeed.SHARED_SEED_LEN * 2:
            return None
        try:
            return SharedSeed(seed_bytes=bytes.fromhex(hex_str))
        except:
            return None

    @staticmethod
    def from_hi_lo(hi, lo):
        hi_b = hi.to_bytes(8, byteorder='big')
        lo_b = lo.to_bytes(8, byteorder='big')
        seed_bytes = hi_b + lo_b
        return SharedSeed(seed_bytes=seed_bytes)

    def __str__(self):
        return self.seed_bytes.hex()

    def get_bytes(self):
        return self.seed_bytes

    def get_hi_lo(self):
        hi = int.from_bytes(self.seed_bytes[0:8], byteorder="big")
        lo = int.from_bytes(self.seed_bytes[8:16], byteorder="big")
        return hi, lo

    def sha256(self, input_bytes):
        return hashlib.sha256(input_bytes).digest()

    def derive_aes256_key(self):
        return self.sha256(self.seed_bytes)

    def derive_rendezvous_id(self):
        aes256_key = self.derive_aes256_key()
        return self.sha256(aes256_key)

