# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import uuid
import json


class ProviderInfo():
    def __init__(self, account_uuid=None, wad=None, payer=True, payee=True,
                 public_keys=[], features=[], feature_data={}):
        self.account_uuid = account_uuid if account_uuid else str(uuid.uuid4())
        self.wad = wad if wad else Wad.bitcoin(0)
        self.payer = payer
        self.payee = payee
        self.public_keys = public_keys
        self.features = features
        self.feature_data = feature_data


    def to_dict(self):
        pass

    def to_json(self):
        json.dumps(self.to_dict())

    @staticmethod
    def from_dict(provider_info_dict):
        pass

    @staticmethod
    def from_json(self, json_str):
        self.from_dict(json.loads(json_str))
