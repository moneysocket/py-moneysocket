#!/usr/bin/env python3
# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import unittest

from moneysocket1.beacon.test_beacon import TestBeaconEncode
from moneysocket1.encoding.test_tlv import TestTlv
from moneysocket1.encoding.test_bigsize import TestBigSize
from moneysocket1.encoding.test_namespace import TestNamespace
from moneysocket1.provider_info.test_wad import TestWad
from moneysocket1.provider_info.test_provider_info import TestProviderInfo
from moneysocket1.message.test_message import TestMessage

if __name__ == '__main__':
    unittest.main()
