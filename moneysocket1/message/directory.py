# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

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
