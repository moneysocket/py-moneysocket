# Copyright (c) 2020 Jarret Dyrbye
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import logging
import uuid

from base64 import b64encode

from twisted.internet import reactor

from moneysocket.lightning.lightning import Lightning

class CLightning(Lightning):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
        self.plugin.add_subscription("invoice_payment",
                                     self.handle_invoice_payment)

    def handle_invoice_payment(self, *args, **kwargs):
        logging.debug("kwargs: %s" % str(kwargs))
        msats = int(str(kwargs['invoice_payment']['msat'])[:-4])
        preimage = kwargs['invoice_payment']['preimage']
        logging.info("recvd payment: msats: %s  preimage: %s" % (
            msats, preimage))
        reactor.callFromThread(self._recv_paid, preimage, msats)

    def _gen_new_label(self):
        label_bytes = uuid.uuid4().bytes
        label_str = b64encode(label_bytes).decode('utf8')
        return label_str

    def get_invoice(self, msat_amount):
        logging.info("getting invoice: %smsats" % msat_amount)
        label = self._gen_new_label()

        try:
            i = self.plugin.rpc.invoice(msat_amount, label, "")
        except Exception as e:
            # TODO - break down failures and give descriptive errro
            return None, str(e)
        logging.info("got: %s" % i)
        return i['bolt11'], None

    def pay_invoice(self, bolt11, request_uuid):
        try:
            result = self.plugin.rpc.pay(bolt11, label=request_uuid)
        except Exception as e:
            # TODO - break down failures and give descriptive errro
            return None, None, str(e)
        preimage = result['payment_preimage']
        paid_msats = result['msatoshi_sent']
        logging.info("success! preimage: %s" % preimage)
        return preimage, paid_msats, None
