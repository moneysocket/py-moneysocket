# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from ..message import Message

class Notification(Message):
    TYPE_NO = 0x1
    TYPE_NAME = "NOTIFICATION"
