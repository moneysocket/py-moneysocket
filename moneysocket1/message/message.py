# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import json
import uuid
import time

from ..version import Version
from ..encoding.tlv import Tlv
from ..encoding.namespace import Namespace
from ..encoding.bigsize import BigSize

from .rfc_types import RFC_MESSAGE_TYPE_NAMES
from .rfc_types import RFC_MESSAGE_TYPE_NUMBERS
from .rfc_types import check_rfc_types

MESSAGE_TLV_TYPE = 0
SENDER_VERSION_TLV_TYPE = 0
MESSAGE_TYPE_TLV_TYPE = 1
LANGUAGE_OBJECT_TLV_TYPE = 2

ONE_HOUR_IN_SECONDS = 60 * 60




class MessageDirectory():
    def __init__(self):
        self.directory = {}
        self.type_names = {}
        self.subtype_names = {}
        self.type_nos = {}
        self.subtype_nos = {}

    def index_no(self, type_no, subtype_no):
        return "%d_%d" % (type_no, subtype_no)

    def index_name(self, message_type_name, message_subtype_name):
        if message_type_name not in self.type_nos:
            return None, "unknown type name"
        if message_subtype_name not in self.subtype_nos:
            return None, "unknown subtype name"
        type_no = self.type_nos[message_type_name]
        subtype_no = self.subtype_nos[message_subtype_name]
        return self.index_no(type_no, subtype_no), None

    def register(self, msg_class):
        self.type_nos[msg_class.TYPE_NAME] = msg_class.TYPE_NO
        self.subtype_nos[msg_class.SUBTYPE_NAME] = msg_class.SUBTYPE_NO

        self.type_names[msg_class.TYPE_NO] = msg_class.TYPE_NAME
        self.subtype_names[msg_class.SUBTYPE_NO] = msg_class.SUBTYPE_NAME

        i = self.index_no(msg_class.TYPE_NO, msg_class.SUBTYPE_NO)
        self.directory[i] = {'class':         msg_class,
                             'type_no':       msg_class.TYPE_NO,
                             'subtype_no':    msg_class.SUBTYPE_NO,
                             'type_name':     msg_class.TYPE_NAME,
                             'subtype_name':  msg_class.SUBTYPE_NAME}

    def has_entry(self, type_name, subtype_name):
        i, err = self.index_name(type_name, subtype_name)
        if err:
            return False
        return i in self.directory

    def lookup_class(self, type_name, subtype_name):
        i, err = self.index_name(type_name, subtype_name)
        return self.directory[i]['class']


MESSAGE_DIRECTORY = MessageDirectory()


class Message():
    def __init__(self, language_object, additional_tlvs=[],
                 sender_version=None):
        self.sender_version = (sender_version if sender_version else
                               Version.this_code_version())
        self.additional_tlvs = additional_tlvs
        self.language_object = language_object


    def to_dict(self):
        return {'type':            self.TYPE_NO,
                'subtype':         self.SUBTYPE_NO,
                'language_object': self.language_object,
                'sender_version':  self.sender_version.to_dict(),
                'additional_tlvs': [tlv.to_dict() for tlv in
                                    self.additional_tlvs]
               }

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True)



    @staticmethod
    def from_dict(message_dict):
        # assume dictionary is already validated
        message_type = message_dict['type']
        message_subtype = message_dict['subtype']
        sender_version = Version.from_dict(message_dict['sender_version'])
        language_object = message_dict['language_object']
        additional_tlvs = [Tlv.from_dict(d) for d in
                           message_dict['additional_tlvs']]
        type_name = message_dict['language_object']['type']
        subtype_name = message_dict['language_object']['subtype']
        c = MESSAGE_DIRECTORY.lookup_class(type_name, subtype_name)
        return c(language_object, additional_tlvs=additional_tlvs,
                 sender_version=sender_version)


    @staticmethod
    def check_uuidv4(uuid_str):
        try:
            u = uuid.UUID(uuid_str)
            if u.version != 4:
                return "uuid is not uuid version 4"
        except Exception as e:
            return "invalid uuid"
        return None


    @staticmethod
    def check_language_object_for_subtype(language_object):
        if "subtype_data" not in language_object:
            return "no subtype data included"
        if type(language_object['subtype_data']) != dict:
            return "subtype_data not of object type"
        if not MESSAGE_DIRECTORY.has_entry(language_object['type'],
                                           language_object['subtype']):
            return "unknown message subtype parser"
        c = MESSAGE_DIRECTORY.lookup_class(language_object['type'],
                                           language_object['subtype'])
        return c.validate_subtype_data(language_object)


    @staticmethod
    def check_language_object_for_type(language_object):
        t = language_object["type"]
        if t == "REQUEST":
            if "request_uuid" not in language_object:
                return "no request_uuid for REQUEST"
            if type(language_object['request_uuid']) != str:
                return "request_uuid is not a string"

            err = Message.check_uuidv4(language_object['request_uuid'])
            if err:
                return None, err
        elif t == "NOTIFICATION":
            if "request_uuid" not in language_object:
                return "no request_uuid for NOTIFICATION"
            rrid = language_object['request_uuid']
            if rrid is not None:
                if type(rrid) != str:
                    return "request_uuid is not a string"
                err = Message.check_uuidv4(rrid)
                if err:
                    return None, err
            # null rrid is allowed, but subtype might not allow it
        else:
            return None, "unknown message type"

        return None

    @staticmethod
    def decode_bytes(message_bytes):
        msg_tlv, remainder, err = Tlv.pop(message_bytes)
        if err:
            return None, err
        if len(remainder) > 0:
            return None, "extra bytes after message TLV"
        if msg_tlv.t != MESSAGE_TLV_TYPE:
            return None, "unknown TLV"
        if not Namespace.tlvs_are_valid(msg_tlv.v):
            return None, "invalid TLVs in message"
        if len(msg_tlv.v) == 0:
            return None, "no TLVs in message"
        # Version TLV
        version_tlv, tlv_stream, _ = Tlv.pop(msg_tlv.v)
        # already validated TLV validity
        if version_tlv.t != SENDER_VERSION_TLV_TYPE:
            return None, "missing sender_version TLV"

        sender_version, err = Version.from_bytes(version_tlv.v)
        if err:
            return None, err

        if len(tlv_stream) == 0:
            return None, "missing message_type TLV"

        # message type TLV
        message_type_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
        # already validated TLV validity
        if message_type_tlv.t != MESSAGE_TYPE_TLV_TYPE:
            return None, "malformed message_type TLV"

        message_type, remainder, err = Namespace.pop_u8(message_type_tlv.v)
        if err:
            return None, "malformed message_type type value"
        message_subtype, remainder, err = BigSize.pop(remainder)
        if len(remainder) != 0:
            return None, "extra bytes in message_type TLV"

        if len(tlv_stream) == 0:
            return None, "missing language_object TLV"
        # language_object TLV
        language_object_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
        # already validated TLV validity
        if language_object_tlv.t != LANGUAGE_OBJECT_TLV_TYPE:
            return None, "malformed language_object TLV"
        try:
            language_object = json.loads(language_object_tlv.v.decode("utf8"))
        except:
            return None, "could not decode json object"

        if "timestamp" not in language_object:
            return None, "timestamp not in json object"
        if type(language_object["timestamp"]) not in {int, float}:
            return None, "timestamp not an integer or float"
        if language_object["timestamp"] < 0:
            return None, "timestamp is not a positive value"
        if language_object["timestamp"] > (time.time() + ONE_HOUR_IN_SECONDS):
            return None, "timestamp in the future"
        if "version" not in language_object:
            return None, "version not in json object"
        if type(language_object["version"]) is not dict:
            return None, "version not an object"
        if "major" not in language_object['version']:
            return None, "version missing major value"
        if type(language_object['version']['major']) != int:
            return None, "version major not integer"
        if language_object['version']['major'] < 0:
            return None, "version major negative"
        if language_object['version']['major'] > 255:
            return None, "version major greater than 255"
        if "minor" not in language_object['version']:
            return None, "version missing minor value"
        if type(language_object['version']['minor']) != int:
            return None, "version minor not integer"
        if language_object['version']['minor'] < 0:
            return None, "version minor negative"
        if language_object['version']['minor'] > 255:
            return None, "version minor greater than 255"
        if "patch" not in language_object['version']:
            return None, "version missing patch value"
        if type(language_object['version']['patch']) != int:
            return None, "version patch not integer"
        if language_object['version']['patch'] < 0:
            return None, "version patch negative"
        if language_object['version']['patch'] > 255:
            return None, "version patch greater than 255"

        if language_object['version']['major'] != sender_version.major:
            return None, "language_object major version doesn't match TLV"
        if language_object['version']['minor'] != sender_version.minor:
            return None, "language_object minor version doesn't match TLV"
        if language_object['version']['patch'] != sender_version.patch:
            return None, "language_object patch version doesn't match TLV"

        if 'features' not in language_object:
            return None, "language_object features value not included"
        if type(language_object['features']) != list:
            return None, "language_object features value must be a list"
        for f in language_object['features']:
            if type(f) != str:
                return None, "language_object features list entry not a string"
        features = language_object['features']
        if type(language_object['feature_data']) != dict:
            return None, "language_object feature_data value must be an object"
        for key, value in language_object['feature_data'].items():
            if key not in set(features):
                return None, "language_object feature_data for unknown feature"
            if value is None:
                return None, "language_object feature_data value is null"

        if "type" not in language_object:
            return None, "language_object missing type"
        if type(language_object["type"]) != str:
            return None, "language_object type is not a string"

        if "subtype" not in language_object:
            return None, "language_object missing subtype"
        if type(language_object["subtype"]) != str:
            return None, "language_object subtype is not a string"
        if language_object["subtype"] == "":
            return None, "language_object subtype is an empty string"

        if language_object['type'] not in RFC_MESSAGE_TYPE_NUMBERS.keys():
            return None, "language_object missing type"


        err = Message.check_language_object_for_type(language_object)
        if err:
            return None, err

        err = Message.check_language_object_for_subtype(language_object)
        if err:
            return None, err

        err = check_rfc_types(message_type, language_object["type"],
                              message_subtype, language_object['subtype'])
        if err:
            return None, err

        additional_tlvs = list(Namespace.iter_tlvs(tlv_stream))

        type_name = language_object['type']
        subtype_name = language_object['subtype']
        c = MESSAGE_DIRECTORY.lookup_class(type_name, subtype_name)
        m = c(language_object, additional_tlvs=additional_tlvs,
              sender_version=sender_version)
        return m, None


    def encode_bytes(self):
        sender_version_tlv = Tlv(SENDER_VERSION_TLV_TYPE,
                                 self.sender_version.encode_bytes()).encode()

        type_bin = Namespace.encode_u8(self.TYPE_NO)
        subtype_bin = BigSize.encode(self.SUBTYPE_NO)
        message_type_tlv = Tlv(MESSAGE_TYPE_TLV_TYPE,
                               type_bin + subtype_bin).encode()

        language_object_tlv = Tlv(
            LANGUAGE_OBJECT_TLV_TYPE,
            json.dumps(self.language_object).encode("utf8")).encode()

        additional_tlvs = b''.join(t.encode() for t in self.additional_tlvs)

        return Tlv(MESSAGE_TLV_TYPE,
                   sender_version_tlv + message_type_tlv +
                   language_object_tlv + additional_tlvs).encode()


class MessageSubtype(Message):
    def __init__(self, language_object, additional_tlvs=[],
                 sender_version=None):
        super().__init__(language_object, additional_tlvs=additional_tlvs,
                         sender_version=sender_version)

    @staticmethod
    def validate_subtype_data(language_object):
        raise NotImplementedError("implement in subclass")



class TransportPing(MessageSubtype):
    TYPE_NO = 0x0
    TYPE_NAME = "REQUEST"
    SUBTYPE_NO = 0x0
    SUBTYPE_NAME = "TRANSPORT_PING"
    def __init__(self, language_object, additional_tlvs=[],
                 sender_version=None):
        super().__init__(language_object, additional_tlvs=additional_tlvs,
                         sender_version=sender_version)

    @staticmethod
    def validate_subtype_data(language_object):
        return None


MESSAGE_DIRECTORY.register(TransportPing)

class TransportPong(MessageSubtype):
    TYPE_NO = 0x1
    TYPE_NAME = "NOTIFICATION"
    SUBTYPE_NO = 0x0
    SUBTYPE_NAME = "TRANSPORT_PONG"
    def __init__(self, language_object, additional_tlvs=[],
                 sender_version=None):
        super().__init__(language_object, additional_tlvs=additional_tlvs,
                         sender_version=sender_version)

    @staticmethod
    def validate_subtype_data(language_object):
        if type(language_object['request_uuid']) is not str:
            return "non-string request uuid for TRANSPORT_PONG"
        err = TransportPong.check_uuidv4(language_object['request_uuid'])
        if err:
            return err
        return None


MESSAGE_DIRECTORY.register(TransportPong)
