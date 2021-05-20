# Copyright (c) 2021 Moneysocket Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

VERSION_MAJOR = 0  # pre-specification protocol v0
VERSION_MINOR = 99 # implementing v1, but still WIP
VERSION_PATCH = 99 # implementing v1, but still WIP

VERSION = ".".join(str(v) for v in [VERSION_MAJOR, VERSION_MINOR,
                                    VERSION_PATCH])

class MoneysocketVersion():
    def __init__(self, major, minor, patch):
        assert major <= 255
        assert minor <= 255
        assert patch <= 255
        self.major = major
        self.minor = minor
        self.patch = patch

    def __str__(self):
        return "v%d.%d.%d" % (self.major, self.minor, self.patch)

    def to_dict(self):
        return {'major': self.major,
                'minor': self.minor,
                'patch': self.patch}

    @staticmethod
    def from_dict(version_dict):
        return MoneysocketVersion(version_dict['major'], version_dict['minor'],
                                  version_dict['patch'])

    def encode_bytes(self):
        return bytes([self.major, self.minor, self.patch])

    @staticmethod
    def from_bytes(encoded_bytes):
        if len(encoded_bytes) != 3:
            return None, "unable to decode version from bytes"
        major = int.from_bytes(encoded_bytes[0:1], byteorder='big')
        minor = int.from_bytes(encoded_bytes[1:2], byteorder='big')
        patch = int.from_bytes(encoded_bytes[2:3], byteorder='big')
        return MoneysocketVersion(major, minor, patch), None

    @staticmethod
    def this_code_version():
        return MoneysocketVersion(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
