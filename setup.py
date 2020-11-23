# Copyright (c) 2020 Jarret Dyrbye
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
from setuptools import setup
from moneysocket.moneysocket import VERSION
import io


packages = ['moneysocket.layer.websocket',
            'moneysocket.layer.rendezvous',
            'moneysocket.layer.local',
            'moneysocket.layer.transact',
            'moneysocket.layer',
            'moneysocket.nexus',
            'moneysocket.nexus.websocket',
            'moneysocket.nexus.rendezvous',
            'moneysocket.nexus.local',
            'moneysocket.nexus.transact',
            'moneysocket.lightning',
            'moneysocket.wad',
            'moneysocket.stack',
            'moneysocket.utl',
            'moneysocket.utl.third_party.bolt',
            'moneysocket.utl.third_party.lightning_payencode',
            'moneysocket.beacon',
            'moneysocket.beacon.location',
            'moneysocket.message',
            'moneysocket.message.notification',
            'moneysocket.message.request']


with io.open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]

setup(name='moneysocket',
      version=VERSION,
      description='Python implementation for Moneysocket protocol',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='http://github.com/moneysocket/py-moneysocket',
      author='Jarret Dyrbye',
      author_email='jarret.dyrbye@gmail.com',
      license='MIT',
      packages=packages,
      scripts=[],
      zip_safe=True,
      install_requires=requirements)
