# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from ..message import Message

class Request(Message):
    TYPE_NO = 0x0
    TYPE_NAME = "REQUEST"
