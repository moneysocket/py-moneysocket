# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php



RFC_REQUEST_SUBTYPE_NUMBERS = {"TRANSPORT_PING": 0x0,
                               "RENDEZVOUS":     0x1,
                              }
RFC_REQUEST_SUBTYPE_NAMES = {v:k for k, v in RFC_REQUEST_SUBTYPE_NUMBERS.items()}
RFC_NOTIFICATION_SUBTYPE_NUMBERS = {"TRANSPORT_PONG":           0x0,
                                    "RENDEZVOUS":               0x1,
                                    "RENDEZVOUS_NOT_READY":     0x2,
                                    "RENDEZVOUS_END":           0x3,
                                   }
RFC_NOTIFICATION_SUBTYPE_NAMES = {v:k for k, v in
                                  RFC_NOTIFICATION_SUBTYPE_NUMBERS.items()}
RFC_MESSAGE_TYPE_NUMBERS = {
    "REQUEST":      {'number':           0x0,
                     'subtypes_by_name': RFC_REQUEST_SUBTYPE_NUMBERS},
    "NOTIFICATION": {'number':           0x1,
                     'subtypes_by_name': RFC_NOTIFICATION_SUBTYPE_NUMBERS},
}
RFC_MESSAGE_TYPE_NAMES = {
    info['number']: {'name':               name,
                     'subtypes_by_number': {v: k for k, v in
                                            info['subtypes_by_name'].items()}
                    } for name, info in RFC_MESSAGE_TYPE_NUMBERS.items()
}


def check_rfc_types(type_number, type_name, subtype_number, subtype_name):
    if type_number not in RFC_MESSAGE_TYPE_NUMBERS:
        if type_name in RFC_MESSAGE_TYPE_NAMES:
            return "rfc type number without matching name"
    if type_name not in RFC_MESSAGE_TYPE_NAMES:
        if type_number in RFC_MESSAGE_TYPE_NUMBERS:
            return "rfc type name without matching number"

    if type_name == "REQUEST":
        if subtype_number not in RFC_REQUEST_SUBTYPE_NUMBERS:
            if subtype_name in RFC_REQUEST_SUBTYPE_NAMES:
                return "rfc request subtype number without matching name"
        if subtype_name not in RFC_REQUEST_SUBTYPE_NAMES:
            if subtype_number in RFC_REQUEST_SUBTYPE_NUMBERS:
                return "rfc request subtype name without matching number"
    elif type_name == "NOTIFICATION":
        if subtype_number not in RFC_NOTIFICATION_SUBTYPE_NUMBERS:
            if subtype_name in RFC_NOTIFICATION_SUBTYPE_NAMES:
                return "rfc request subtype number without matching name"
        if subtype_name not in RFC_NOTIFICATION_SUBTYPE_NAMES:
            if subtype_number in RFC_NOTIFICATION_SUBTYPE_NUMBERS:
                return "rfc notification subtype name without matching number"
    return None

def is_rfc_type(type_name, subtype_name):
    if type_name in RFC_MESSAGE_TYPE_NAMES:
        if (subtype_name in
            RFC_MESSAGE_TYPE_NUMBERS[type_names]['subtypes_by_name']):
            return True
    return False

