# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import json

from ..version import Version
from ..encoding.tlv import Tlv
from ..encoding.namespace import Namespace
from ..encoding.bigsize import BigSize

from .rfc_types import RFC_MESSAGE_TYPE_NAMES
from .rfc_types import RFC_MESSAGE_TYPE_NUMBERS

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
                             'subtype_name':  msg_class.SUBTYPE_NAME,
                             'validate_func': msg_class.validate_func}

    def has_entry(self, type_no, subtype_no):
        i = MessageDirectory.index_no(type_no, subtype_no)
        return i in self.directory


class Message():
    MESSAGE_TYPES = {}

    def __init__(self, message_type, message_subtype, language_object,
                 additional_tlvs=[], sender_version=None):
        self.type = message_type
        self.subtype = message_subtype
        self.sender_version = (sender_version if sender_version else
                               Version.this_code_version())
        self.additional_tlvs = additional_tlvs
        self.language_object = language_object


    def to_dict(self):
        return {'type':            self.message_type,
                'subtype':         self.message_subtype,
                'language_object': self.language_object,
                'sender_version':  self.sender_version.to_dict(),
                'additional_tlvs': [tlv.to_dict() for tlv in
                                    self.additional_tlvs]
               }

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True)


    @staticmethod
    def from_dict(message_dict):
        message_type = message_dict['type']
        message_subtype = message_dict['subtype']
        sender_version = Version.from_dict(message_dict['sender_version'])
        language_object = message_dict['language_object']
        additional_tlvs = [Tlv.from_dict(d) for d in
                           message_dict['additional_tlvs']]
        return Message(message_type, message_subtype, language_object,
                       additional_tlvs=additional_tlvs,
                       sender_version=sender_version)


    @staticmethod
    def decode_bytes(message_bytes):
        t, tlv_stream, err = Tlv.pop(message_bytes)
        if err:
            return None, err
        if t != MESSAGE_TLV_TYPE:
            return None, "unknown TLV"
        if not Namespace.tlvs_are_valid(tlv_stream):
            return None, "invalid TLVs in message"
        if len(tlv_stream) == 0:
            return None, "no TLVs in message"
        # Version TLV
        version_tlv, tlv_stream, _ = Tlv.pop(tlv_stream)
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

        message_type, remainder, err = Namespace.pop_u8(message_type.v)
        if err:
            return None, "malformed message_type type value"
        message_type, remainder, err = Namespace.pop_u8(message_type.v)
        if err:
            return None, "malformed message_type subtype value"
        message_subtype, remainder, err = BigSize.pop(remainder)
        if len(remainder) != 0:
            return None, "extra bytes in message_type TLV"
        #if message_type not in RFC_MESSAGE_TYPE_NAMES.keys():
        #    return None, "unknown message type"
        #if message_subtype not in self.MESSAGE_TYPES[message_type]:
        #    return None, "unknown message subtype"

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
        if len(language_object['version']['major']) != int:
            return None, "version major not integer"
        if language_object['version']['major'] < 0:
            return None, "version major negative"
        if language_object['version']['major'] > 255:
            return None, "version major greater than 255"
        if "minor" not in language_object['version']:
            return None, "version missing minor value"
        if len(language_object['version']['minor']) != int:
            return None, "version minor not integer"
        if language_object['version']['minor'] < 0:
            return None, "version minor negative"
        if language_object['version']['minor'] > 255:
            return None, "version minor greater than 255"
        if "patch" not in language_object['version']:
            return None, "version missing patch value"
        if len(language_object['version']['patch']) != int:
            return None, "version patch not integer"
        if language_object['version']['patch'] < 0:
            return None, "version patch negative"
        if language_object['version']['patch'] > 255:
            return None, "version patch greater than 255"
        if language_object['version']['major'] != version.major:
            return None, "language_object major version doesn't match TLV"
        if language_object['version']['minor'] != version.minor:
            return None, "language_object minor version doesn't match TLV"
        if language_object['version']['patch'] != version.patch:
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
        if language_object["subtype"] != "":
            return None, "language_object subtype is an empty string"

        if language_object['type'] not in MESSAGE_TYPE_NUMBERS.keys():
            return None, "language_object missing type"

        # does number match name?
        # does name match number?
        # does tlv number match language object?
        # does number and name fit rfc types?
        # is number and name registered with a parser?
        # does registered parser succeed without error?



        additional_tlvs = list(Namespace.iter_tlvs(tlv_stream))
        return Message(message_type, message_subtype, language_object,
                       additional_dlvs=additional_tlvs,
                       sender_version=sender_version)


    def encode_bytes(self):
        sender_version_tlv = Tlv(SENDER_VERSION_TLV_TYPE,
                                 self.sender_version.encode_bytes()).encode()

        type_bin = Namespace.encode_u8(self.type)
        subtype_bin = BigSize.encode(self.subtype)
        message_type_tlv = Tlv(MESSAGE_TYPE_TLV_TYPE,
                               type_bin + subtype_bin).encode()

        language_object_tlv = Tlv(
            LANGUAGE_OBJECT_TLV_TYPE,
            json.dumps(self.language_object).encode("utf8")).encode()

        additional_tlvs = b''.join(t.encode() for t in self.additional_tlvs)

        return Tlv(MESSAGE_TLV_TYPE,
                   sender_version_tlv + message_type_tlv +
                   language_object_tlv + additional_tlvs).encode()
