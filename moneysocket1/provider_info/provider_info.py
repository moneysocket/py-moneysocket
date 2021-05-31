# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import uuid
import json

from .wad import Wad


class PublicKeys():
    def __init__(self, curve, features, friendly_name):
        self.curve = curve
        self.features = features
        self.friendly_name = friendly_name


class ProviderInfo():
    def __init__(self, account_uuid=None, wad=None, payer=True, payee=True,
                 public_keys=[], features=[], feature_data={},
                 additional_key_values={}):
        self.account_uuid = account_uuid if account_uuid else str(uuid.uuid4())
        self.wad = wad if wad else Wad.bitcoin(0)
        self.payer = payer
        self.payee = payee
        self.public_keys = public_keys
        self.features = features
        self.feature_data = feature_data
        self.additional_key_values = additional_key_values

    def to_dict(self):
        d = {'account_uuid': self.account_uuid,
             'wad':          self.wad.to_dict(),
             'payer':        self.payer,
             'payee':        self.payee,
             'public_keys':  self.public_keys,
             'features':     self.features,
             'feature_data': self.feature_data}
        d.update(self.additional_key_values)
        return d


    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True, indent=1)

    def __str__(self):
        return self.to_json()

    @staticmethod
    def from_dict(pi_dict):
        if 'account_uuid' not in pi_dict:
            return None, "no account_uuid included"
        if type(pi_dict['account_uuid']) != str:
            return None, "account_uuid type is not a string"
        try:
            u = uuid.UUID(pi_dict['account_uuid'])
            if u.version != 4:
                return None, "account_uuid is not uuid version 4"
        except Exception as e:
            return None, "invalid account_uuid"
        if 'wad' not in pi_dict:
            return None, "wad value not included"
        if type(pi_dict['wad']) != dict:
            return None, "wad value not an object"
        wad, err = Wad.from_dict(pi_dict['wad'])
        if err:
            return None, "invalid wad: %s" % err
        if 'payee' not in pi_dict:
            return None, "no payee setting included"
        if type(pi_dict['payee']) != bool:
            return None, "payee must be boolean type"
        if 'payer' not in pi_dict:
            return None, "no payer setting included"
        if type(pi_dict['payer']) != bool:
            return None, "payer must be boolean type"
        if 'features' not in pi_dict:
            return None, "features value not included"
        if type(pi_dict['features']) != list:
            return None, "features value must be a list"
        for f in pi_dict['features']:
            if type(f) != str:
                return None, "features list entry not a string"
        features = pi_dict['features']
        if type(pi_dict['feature_data']) != dict:
            return None, "features value must be an object"
        for key, value in pi_dict['feature_data'].items():
            if key not in set(features):
                return None, "feature_data for undeclared feature"
            if value is None:
                return None, "feature_data value is null"
        if 'public_keys' not in pi_dict:
            return None, "public_keys value not included"
        if type(pi_dict['public_keys']) != dict:
            return None, "public_keys value not object type"
        for key, value in pi_dict['public_keys'].items():
            try:
                _ = bytes.fromhex(key)
            except:
                return None, "public key not interpretable as bytes"
            if type(value) != dict:
                return None, "public key info value not object type"
            if 'curve' not in value:
                return None, "curve of public key not specified"
            if type(value['curve']) != str:
                return None, "curve value not a string"
            if value['curve'] == "":
                return None, "curve value is an empty string"
            if 'friendly_name' in value:
                if type(value['friendly_name']) != str:
                    return None, "friendly_name value is not a string"
                if value['friendly_name'] == "":
                    return None, "friendly_name value is empty string"
                if len(value['friendly_name']) > 64:
                    return None, "friendly_name string is longer than 64 chars"
            if 'features' not in value:
                return None, "features list not included in object"
            if type(value['features']) != list:
                return None, "features value not an array"
            for f in value['features']:
                if type(f) != str:
                    return None, "feature string not a string"
                if f == "":
                    return None, "feature string an empty string"

        additional_key_values = {}
        for key, value in pi_dict.items():
            if key in {'account_uuid', 'wad', 'payee', 'payer', 'public_keys',
                       'features', 'feature_data'}:
                continue
            additional_key_values[key] = value
        pi = ProviderInfo(account_uuid=pi_dict['account_uuid'], wad=wad,
                          payer=pi_dict['payer'], payee=pi_dict['payee'],
                          public_keys=pi_dict['public_keys'], features=features,
                          feature_data=pi_dict['feature_data'],
                          additional_key_values=additional_key_values)
        return pi, None

    @staticmethod
    def from_json(self, json_str):
        self.from_dict(json.loads(json_str))
