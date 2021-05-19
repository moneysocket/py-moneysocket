# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from ...encoding.tlv import Tlv
from ...encoding.namespace import Namespace
from ...encoding.bigsize import BigSize

WEBSOCKET_LOCATION_TLV_TYPE = 0

GENERATOR_PREFERENCE_TLV_TYPE = 0
DEFAULT_GENERATOR_PREFERENCE = 255

HOSTNAME_TLV_TYPE = 1
USE_TLS_TLV_TYPE = 2
USE_TLS_ENUM_VALUE = {0: False,
                      1: True}
PORT_TLV_TYPE = 3
DEFAULT_TLS_PORT = 443
DEFAULT_NO_TLS_PORT = 80
PORT_TLV_TYPE = 4
DEFAULT_PATH = ""

class WebsocketLocation():
    def __init__(self, host, port=None, use_tls=True, path=None,
                 generator_preference=None):
        self.use_tls = use_tls
        self.host = host
        self.port = port if port else (DEFAULT_TLS_PORT if use_tls else
                                       DEFAULT_NO_TLS_PORT)
        self.path = path if path else DEFAULT_PATH
        while self.path.startswith("/"):
            self.path = self.path[1:]
        self.generator_preference = (generator_preference if
                                     generator_preference else
                                     DEFAULT_GENERATOR_PREFERENCE)
        assert self.generator_preference >= 0
        assert self.generator_preference <= 255

    def __str__(self):
        return "%s://%s:%s%s" % ("wss" if self.use_tls else "ws", self.host,
                                 self.port, self.path)

    def to_dict(self):
        return {'generator_preference': self.generator_preference,
                'type':                 "WebSocket",
                'host':                 self.host,
                'port':                 self.port,
                'use_tls':              self.use_tls,
                'path':                 self.path}

    def is_tls(self):
        return self.use_tls

    @staticmethod
    def parse_location(tlv):
        assert tlv.t == WEBSOCKET_LOCATION_TLV_TYPE

        first_tlv, tlv_stream, err = Tlv.pop(tlv.v)
        if err:
            return None, err
        if first_tlv.t not in {GENERATOR_PREFERENCE_TLV_TYPE,
                               HOSTNAME_TLV_TYPE}:
            return None,  "unknown TLV"

        if first_tlv.t == GENERATOR_PREFERENCE_TLV_TYPE:
            generator_preference, gp_remainder, err = (
            Namespace.pop_u8(first_tlv.v))
            if err:
                return None, "unable to parse role hint"
            if len(gp_remainder) != 0:
                return None, "extra role_hint_remainder bytes"
            hostname_tlv, tlv_stream, err = Tlv.pop(tlv_stream)
            if err:
                return None, "unable to parse hostname TLV"
            if hostname_tlv.t != HOSTNAME_TLV_TYPE:
                return None, "unknown TLV type"
        else:
            generator_preference = None
            hostname_tlv = first_tlv

        try:
            hostname = hostname_tlv.v.decode("utf8", errors="strict")
        except:
            return None, "error decoding host string"

        # TODO
        port = 0
        use_tls = True
        path = "ws"
        location = WebsocketLocation(hostname, port=port, use_tls=use_tls,
                                     path=path,
                                     generator_preference=generator_preference)
        return location, None

    def encode_tlv(self):
        tlv_stream = b''
        if self.generator_preference != DEFAULT_GENERATOR_PREFERENCE:
            tlv_stream += (
                Tlv(Namespace.encode_u8(self.generator_preference)).encode())
        tlv_stream += Tlv(HOSTNAME_TLV_TYPE, self.host.encode("utf8")).encode()
        if not self.use_tls:
            tlv_stream += Tlv(USE_TLS_TLV_TYPE, BigSize.encode(0)).encode()
            if self.port != DEFAULT_NO_TLS_PORT:
                tlv_stream += Tlv(PORT_TLV_TYPE,
                                  BigSize.encode(self.port)).encode()
        else:
            if self.port != DEFAULT_TLS_PORT:
                tlv_stream += Tlv(PORT_TLV_TYPE,
                                  BigSize.encode(self.port)).encode()

        return Tlv(WEBSOCKET_LOCATION_TLV_TYPE, tlv_stream).encode()




    #@staticmethod
    #def from_tlv(tlv):
    #    assert tlv.t == WebsocketLocation.WEBSOCKET_LOCATION_TLV_TYPE
    #    tlvs = {tlv.t: tlv for tlv in Namespace.iter_tlvs(tlv.v)}
    #    if HOST_TLV_TYPE not in tlvs.keys():
    #        return None, "no host tlv given"
    #    try:
    #        host = tlvs[HOST_TLV_TYPE].v.decode("utf8", errors="strict")
    #    except:
    #        return None, "error decoding host string"
    #
    #    if USE_TLS_TLV_TYPE not in tlvs.keys():
    #        use_tls = True
    #    else:
    #        enum_value, remainder, err = BigSize.pop(tlvs[USE_TLS_TLV_TYPE].v)
    #        if err:
    #            return None, err
    #        if enum_value not in USE_TLS_ENUM_VALUE.keys():
    #            return None, "error decoding use_tls setting"
    #        use_tls = USE_TLS_ENUM_VALUE[enum_value]
#
#        if PORT_TLV_TYPE not in tlvs.keys():
#            port = DEFAULT_TLS_PORT if use_tls else DEFAULT_NO_TLS_PORT
#        else:
#            port, _, err = BigSize.pop(tlvs[PORT_TLV_TYPE].v)
#            if err:
#                return None, err
#        return WebsocketLocation(host, port=port, use_tls=use_tls), None
#
#    def encode_tlv(self):
#        encoded = Tlv(HOST_TLV_TYPE, self.host.encode("utf8")).encode()
#        if not self.use_tls:
#            encoded += Tlv(USE_TLS_TLV_TYPE, BigSize.encode(0)).encode()
#            if self.port != DEFAULT_NO_TLS_PORT:
#                encoded += Tlv(PORT_TLV_TYPE,
#                               BigSize.encode(self.port)).encode()
#        else:
#            if self.port != DEFAULT_TLS_PORT:
#                encoded += Tlv(PORT_TLV_TYPE,
#                               BigSize.encode(self.port)).encode()
#
#        return Tlv(WebsocketLocation.WEBSOCKET_LOCATION_TLV_TYPE,
#                   encoded).encode()
