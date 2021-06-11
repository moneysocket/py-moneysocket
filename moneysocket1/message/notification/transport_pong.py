# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from ..directory import MESSAGE_DIRECTORY
from .notification import Notification


class TransportPong(Notification):
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
