# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import unittest

from .beacon import Beacon
from .beacon import ROLE_HINT_PROVIDER_GENERATOR_SEEKING_CONSUMER
from .beacon import ROLE_HINT_CONSUMER_GENERATOR_SEEKING_PROVIDER
from .beacon import ROLE_HINT_AUTOMATIC_GENERATOR


class TestBeaconEncode(unittest.TestCase):
    def test_boof(self):
        b = Beacon(role_hint=ROLE_HINT_AUTOMATIC_GENERATOR)
        b1_32 = b.to_bech32()
        print(b1_32)
        b1_j = b.to_json()
        print(b1_j)

        b2, err = Beacon.from_bech32(b1_32)
        print(err)

        print(b2.to_json())
        #self.assertEqual("abcggg", "ggg")
