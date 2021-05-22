# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from .unknown import UnknownLocation
from .websocket import WebsocketLocation
from .websocket import WEBSOCKET_LOCATION_TLV_TYPE

from ...encoding.namespace import Namespace
from ...encoding.tlv import Tlv


LOCATION_PARSERS = {
    WEBSOCKET_LOCATION_TLV_TYPE: WebsocketLocation.parse_location,
}

LOCATION_LIST_TLV_TYPE = 3

class LocationList():
    @staticmethod
    def parse_locations(tlv_stream):
        if not Namespace.tlvs_are_valid(tlv_stream):
            return None, "invalid location_list"
        locations = []
        for tlv in Namespace.iter_tlvs(tlv_stream):
            if tlv.t in LOCATION_PARSERS.keys():
                location, err = LOCATION_PARSERS[tlv.t](tlv)
            else:
                location, err = UnknownLocation.parse_location(tlv)
            if err:
                return None, err
            locations.append(location)
        if len(locations) == 0:
            return None, "no locations in location_list"
        known = sum(1 for l in locations if
                    l.to_dict()['location_type'] != "Unknown")
        if known == 0:
            return None, "no known locations in location_list"
        return locations, None

    @staticmethod
    def encode_tlv_stream(locations):
        b = b''
        for l in locations:
            b += l.encode_tlv()
        return b

    @staticmethod
    def encode_tlv(locations):
        tlv_stream = LocationList.encode_tlv_stream(locations)
        return Tlv(LOCATION_LIST_TLV_TYPE, tlv_stream).encode()

    @staticmethod
    def from_dict_list(dict_locations):
        # NOTE: this is not very strict and is not informative with errors
        locations = []
        for dict_location in dict_locations:
            if dict_location['location_type'] == "WebSocket":
                locations.append(WebsocketLocation.from_dict(dict_location))
            if dict_location['location_type'] == "Unknown":
                locations.append(UnknownLocation.from_dict(dict_location))
        return locations
