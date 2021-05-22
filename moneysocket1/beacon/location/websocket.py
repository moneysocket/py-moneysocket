# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import re
from urllib.parse import urlparse

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
PATH_TLV_TYPE = 4
DEFAULT_PATH = ""

ALLOWED_HOSTNAME_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

class WebsocketLocation():
    def __init__(self, hostname, port=None, use_tls=True, path=None,
                 generator_preference=None):
        self.use_tls = use_tls
        self.hostname = hostname
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
        return "%s://%s:%s%s" % ("wss" if self.use_tls else "ws", self.hostname,
                                 self.port,
                                 ("" if self.path == DEFAULT_PATH else
                                  "/" + self.path))

    def is_tls(self):
        return self.use_tls

    ###########################################################################

    def to_dict(self):
        return {'generator_preference': self.generator_preference,
                'location_type':        "WebSocket",
                'hostname':             self.hostname,
                'port':                 self.port,
                'use_tls':              self.use_tls,
                'path':                 self.path}

    @staticmethod
    def from_dict(location_dict):
        return WebsocketLocation(location_dict['hostname'],
                                 location_dict['port'],
                                 location_dict['use_tls'],
                                 location_dict['path'],
                                 location_dict['generator_preference'])

    ###########################################################################

    @staticmethod
    def valid_hostname(hostname):
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        if len(hostname) > 253:
            return False
        labels = hostname.split(".")
        if re.match(r"[0-9]+$", labels[-1]):
            return False
        return all(ALLOWED_HOSTNAME_RE.match(label) for label in labels)

    @staticmethod
    def valid_url(url):
        try:
            p = urlparse(url)
            #print(p)
        except:
            return False
        return True

    ###########################################################################

    @staticmethod
    def parse_location(tlv):
        assert tlv.t == WEBSOCKET_LOCATION_TLV_TYPE
        if not Namespace.tlvs_are_valid(tlv.v):
            return None, "invalid websocket location TLVs"

        if len(tlv.v) == 0:
            return None, "no websocket location TLVs"

        first_tlv, tlv_stream, _ = Tlv.pop(tlv.v)
        # already validate TLV validity
        if first_tlv.t not in {GENERATOR_PREFERENCE_TLV_TYPE,
                               HOSTNAME_TLV_TYPE}:
            return None, "unknown TLV"
        if first_tlv.t == GENERATOR_PREFERENCE_TLV_TYPE:
            generator_preference, gp_remainder, err = (
            Namespace.pop_u8(first_tlv.v))
            if err:
                return None, "unable to parse generator_preference"
            if len(gp_remainder) != 0:
                return None, "extra generator_preference bytes"
            if generator_preference == 255:
                return None, "generator_preference not minimally encoded"
            if len(tlv_stream) == 0:
                return None, "missing hostname TLV"
            hostname_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
            # already validate TLV validity
            if hostname_tlv.t != HOSTNAME_TLV_TYPE:
                return None, "unknown TLV type"
        else:
            generator_preference = None
            hostname_tlv = first_tlv
        try:
            hostname = hostname_tlv.v.decode("utf8", errors="strict")
        except:
            return None, "error decoding hostname string"
        if not WebsocketLocation.valid_hostname(hostname):
            return None, "invalid hostname"
        port = None
        use_tls = True
        path = None
        while len(tlv_stream) > 0:
            tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
            # already validate TLV validity
            if tlv.t not in {USE_TLS_TLV_TYPE, PORT_TLV_TYPE, PATH_TLV_TYPE}:
                return None, "unknown TLV type"
            if tlv.t == USE_TLS_TLV_TYPE:
                use_tls_byte, remainder, err = Namespace.pop_u8(tlv.v)
                if err:
                    return None, err
                if use_tls_byte not in {0x00, 0x01}:
                    return None, "unknown use_tls setting"
                if len(remainder) > 0:
                    return None, "extra use_tls bytes"
                if use_tls_byte == 0x01:
                    return None, "use_tls not minimally encoded"
                use_tls = use_tls_byte != 0x00
            if tlv.t == PORT_TLV_TYPE:
                port_bigsize, remainder, err = BigSize.pop(tlv.v)
                if err:
                    return None, err
                if len(remainder) > 0:
                    return None, "extra port bytes"
                if port_bigsize > 65535:
                    return None, "port value too large"
                port = port_bigsize
                if use_tls == False and port == 80:
                    return None, "port not minimally encoded"
                if use_tls == True and port == 443:
                    return None, "port not minimally encoded"
            if tlv.t == PATH_TLV_TYPE:
                try:
                    path = tlv.v.decode("utf8", errors="strict")
                except:
                    return None, "error decoding path"
                if len(path) == 0:
                    return None, "path not minimally encoded"
        url_path = "" if (path is None or path == DEFAULT_PATH) else "/" + path
        url_port = port if port else (DEFAULT_TLS_PORT if use_tls else
                                      DEFAULT_NO_TLS_PORT)

        url = "%s://%s:%s%s" % ("wss" if use_tls else "ws", hostname, url_port,
                                url_path)
        #print(url)
        if not WebsocketLocation.valid_url(url):
            return None, "invalid url"
        location = WebsocketLocation(hostname, port=port, use_tls=use_tls,
                                     path=path,
                                     generator_preference=generator_preference)
        return location, None

    def encode_tlv(self):
        tlv_stream = b''
        if self.generator_preference != DEFAULT_GENERATOR_PREFERENCE:
            tlv_stream += (
                Tlv(GENERATOR_PREFERENCE_TLV_TYPE,
                    Namespace.encode_u8(self.generator_preference)).encode())
        tlv_stream += Tlv(HOSTNAME_TLV_TYPE,
                          self.hostname.encode("utf8")).encode()
        if not self.use_tls:
            tlv_stream += Tlv(USE_TLS_TLV_TYPE, BigSize.encode(0)).encode()
            if self.port != DEFAULT_NO_TLS_PORT:
                tlv_stream += Tlv(PORT_TLV_TYPE,
                                  BigSize.encode(self.port)).encode()
        else:
            if self.port != DEFAULT_TLS_PORT:
                tlv_stream += Tlv(PORT_TLV_TYPE,
                                  BigSize.encode(self.port)).encode()
        if self.path != DEFAULT_PATH:
            tlv_stream += Tlv(PATH_TLV_TYPE,
                              self.path.encode("utf8")).encode()
        return Tlv(WEBSOCKET_LOCATION_TLV_TYPE, tlv_stream).encode()
