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



#def classify_number_name(type_number, type_name, subtype_number, subtype_name):
#    if type_number not in RFC_MESSAGE_TYPE_NAMES.keys():
#        return "UNKNOWN"
#    if RFC_MESSAGE_TYPE_NAMES[type_number]['name'] != type_name:
#
#def is_rfc_type(type_number, type_name, subtype_number, subtype_name):
#    pass

#print(RFC_REQUEST_SUBTYPE_NUMBERS)
#print(RFC_REQUEST_SUBTYPE_NAMES)
#print(RFC_NOTIFICATION_SUBTYPE_NUMBERS)
#print(RFC_NOTIFICATION_SUBTYPE_NAMES)


#print(RFC_MESSAGE_TYPE_NAMES)
#print(RFC_MESSAGE_TYPE_NUMBERS)



