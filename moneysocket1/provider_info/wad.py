# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import json

from .fiat import FIAT
from .cryptocurrency import CRYPTOCURRENCY
from .rate import Rate

BTC = {"code":      "BTC",
       "decimals":  0,
       "iso_num":   None,
       "name":      "Bitcoin",
       "symbol":    "₿"}

CODES_WITH_ISO_NUM_ASSIGNED = set(FIAT.keys())

MSAT_PER_SAT = 1000.0
SATS_PER_BTC = 100000000.0
MSAT_PER_BTC = SATS_PER_BTC * MSAT_PER_SAT

class NonBtc():
    def __init__(self, units, name, rate_timestamp=None, code=None,
                 iso_num=None, symbol=None, fmt_decimals=None):
        self.units = units
        self.name = name
        self.rate_timestamp = rate_timestamp
        self.code = code
        self.iso_num = iso_num
        self.symbol = symbol
        self.fmt_decimals = fmt_decimals

    def to_dict(self):
        d = {'units': self.units,
             'name': self.name}
        d['code'] = self.code if self.code else ""
        d['symbol'] = self.symbol if self.symbol else ""
        if self.rate_timestamp:
            d['rate_timestamp'] = self.rate_timestamp
        if self.iso_num:
            d['iso_num'] = self.iso_num
        if self.fmt_decimals:
            d['fmt_decimals'] = self.fmt_decimals
        return d

    @staticmethod
    def from_dict(non_btc_dict):
        if 'units' not in non_btc_dict:
            return None, "no units value"
        if type(non_btc_dict['units']) not in {float, int}:
            return "units not integer or float"
        units = non_btc_dict['units']
        if 'name' not in non_btc_dict:
            return None, "no name value"
        if type(non_btc_dict['name']) != str:
            return None, "name value not string"
        if non_btc_dict['name'] == "":
            return None, "name value is empty string"
        name = non_btc_dict['name']
        rate_timestamp = None
        code = None
        iso_num = None
        symbol = None
        fmt_decimals = None
        if 'rate_timestamp' in non_btc_dict:
            if type(non_btc_dict['rate_timestamp']) not in {float, int}:
                return None, "rate_timestamp not integer or float"
            if non_btc_dict['rate_timestamp'] < 0:
                return None, "rate_timestamp negative"
            rate_timestamp = non_btc_dict['rate_timestamp']
        if 'iso_num' in non_btc_dict:
            if type(non_btc_dict['iso_num']) != int:
                return None, "iso_num not iteger"
            if non_btc_dict['iso_num'] < 0:
                return None, "iso_num not positive"
            iso_num = non_btc_dict['iso_num']
            if 'code' not in non_btc_dict:
                return None, "iso_num without code"
            if type(non_btc_dict['code']) != str:
                return None, "code value with iso_num not string"
            if non_btc_dict['code'] == "":
                return None, "code value with iso_num is empty string"
        else:
            if non_btc_dict['code'] in CODES_WITH_ISO_NUM_ASSIGNED:
                return None, 'using non-standard code with iso_num assigned'
        if 'code' not in non_btc_dict:
            return None, "code value not set"
        if type(non_btc_dict['code']) != str:
            return None, "code value with is string"
        if non_btc_dict != "" and len(non_btc_dict['code']) > 12:
            return None, "code value longer than twelve characters"
        if non_btc_dict != "" and len(non_btc_dict['code']) < 3:
            return None, "code value less than three characters"
        code = non_btc_dict['code']
        if 'symbol' not in non_btc_dict:
            return None, "symbol value not set"
        if type(non_btc_dict) != str:
            return None, "symbol value not string type"
        if len(non_btc_dict['symbol']) > 6:
            return None, "symbol value string too long"
        symbol = non_btc_dict['symbol']
        if 'fmt_decimals' in non_btc_dict:
            if type(non_btc_dict['fmt_decimals']) != int:
                return None, "fmt_decimals not integer"
            if non_btc_dict['fmt_decimals'] < 0:
                return None, "fmt_decimals negative value"
            if non_btc_dict['fmt_decimals'] > 12:
                return None, "fmt_decimals too large"
            fmt_decimals = non_btc_dict['fmt_decimals']
        non_btc = NonBtc(units, name, rate_timestamp=rate_timestamp, code=code,
                         iso_num=iso_num, symbol=symbol,
                         fmt_decimals=fmt_decimals)
        return non_btc, None


class Wad():
    def __init__(self, msat, non_btc=None):
        self.msat = msat
        self.non_btc = non_btc

    def __str__(self):
        if not self.non_btc:
            sats = self.msat / MSAT_PER_SAT
            return "₿ %.3f sat" % sats
        symb = ("%s " % self.non_btc.symbol if
                (self.non_btc.symbol and self.non_btc.symbol != "") else "")
        if self.non_btc.fmt_decimals is not None:
            ufmt = "%." + str(self.non_btc.fmt_decimals) + "f"
            units = ufmt % self.non_btc.units
        else:
            units = "%d" % (round(self.non_btc.units))
        code = " %s" % self.non_btc.code if self.non_btc.code != "" else ""
        return "%s%s%s" % (symb, units, code)

    def to_dict(self):
        d = {'msat': self.msat}
        d['non_btc'] = self.non_btc.to_dict() if self.non_btc else None
        return d

    @staticmethod
    def from_dict(wad_dict):
        if 'msat' not in wad_dict:
            return None, "no msat value given"
        if type(wad_dict['msat']) not in {float, int}:
            return None, "invalid type of msat value"
        if 'non_btc' not in wad_dict:
            return None, "no wad_dict value given"
        non_btc = None
        if wad_dict['non_btc']:
            non_btc, err = NonBtc.from_dict(wad_dict['non_btc'])
            if err:
                return err, None
        if len(wad_dict.keys()) != 2:
            return None, "extra keys in wad_dict"
        return Wad(wad_dict['msat'], non_btc=non_btc), None

    @staticmethod
    def from_json(wad_json):
        try:
            wad_dict = json.loads(wad_json)
        except:
            return None, "could not parse wad json"
        return Wad.from_dict(wad_json)

    def to_json(self):
        d = self.to_dict()
        return json.dumps(d, sort_keys=True, indent=1)

    @staticmethod
    def bitcoin(msat):
        return Wad(msat)

    @staticmethod
    def bitcoin_btc(btc):
        return Wad(btc * MSAT_PER_BTC)

    @staticmethod
    def bitcoin_sat(sat):
        return Wad(sat * MSAT_PER_SAT)

    @staticmethod
    def bitcoin_from_postfix_string(msat_string):
        if msat_string.endswith("msat"):
            try:
                msat = int(msat_string[:-4])
            except:
                return None, "could not parse msat value"
        elif msat_string.endswith("msats"):
            try:
                msat = int(msat_string[:- 5])
            except:
                return None, "could not parse msat value"
        elif msat_string.endswith("sat"):
            try:
                msat = 1000 * int(msat_string[:-3])
            except:
                return None, "could not parse msat value"
        elif msat_string.endswith("sats"):
            try:
                msat = 1000 * int(msat_string[:-4])
            except:
                return None, "could not parse msat value"
        else:
            try:
                msat = int(msat_string)
            except:
                return None, "could not parse msat value"
        if msat < 0:
            return None, "invalid msatoshis value"
        return Wad.bitcoin(msats), None

    @staticmethod
    def usd(usd, rate_btcusd):
        btc, code = rate_btcusd.convert(usd, "USD")
        if code != "BTC":
            return None, "could not get bicoin from rate"
        msat = btc * MSAT_PER_BTC
        u = FIAT['USD']
        non_btc = NonBtc(usd, u['name'], timestamp=rate_btcusd['timestamp'],
                         code=u['code'], iso_num=u['iso_num'],
                         symbol=u['symbol'], fmt_decimals=u['fmt_decimals'])

        return Wad(msat, non_btc=non_btc)
