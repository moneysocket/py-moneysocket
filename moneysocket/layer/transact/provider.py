# Copyright (c) 2020 Jarret Dyrbye
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from moneysocket.layer.layer import Layer
from moneysocket.nexus.transact.provider import ProviderTransactNexus


class ProviderTransactLayer(Layer):
    def __init__(self):
        super().__init__()
        self.handleinvoicerequest = None
        self.handlepayrequest = None
        self.handleproviderinforequest = None
        self.nexuses_by_shared_seed = {}

    def setup_transact_nexus(self, below_nexus):
        n = ProviderTransactNexus(below_nexus, self)
        n.handleinvoicerequest = self.handle_invoice_request
        n.handlepayrequest = self.handle_pay_request
        return n

    ###########################################################################

    def announce_nexus(self, below_nexus):
        provider_transact_nexus = self.setup_transact_nexus(below_nexus)
        self._track_nexus(provider_transact_nexus, below_nexus)
        self._track_nexus_announced(provider_transact_nexus)
        if self.onannounce:
            self.onannounce(provider_transact_nexus)
        shared_seed = provider_transact_nexus.get_shared_seed()
        if shared_seed not in self.nexuses_by_shared_seed:
            self.nexuses_by_shared_seed[shared_seed] = set()
        self.nexuses_by_shared_seed[shared_seed].add(
            provider_transact_nexus.uuid)

    def revoke_nexus(self, below_nexus):
        provider_transact_nexus = self.nexuses[
            self.nexus_by_below[below_nexus.uuid]]
        super().revoke_nexus(below_nexus)
        shared_seed = provider_transact_nexus.get_shared_seed()
        self.nexuses_by_shared_seed[shared_seed].remove(
            provider_transact_nexus.uuid)

    ###########################################################################

    def handle_invoice_request(self, provider_transact_nexus, msats,
                               request_uuid):
        assert self.handleinvoicerequest
        self.handleinvoicerequest(provider_transact_nexus, msats, request_uuid)

    def handle_pay_request(self, provider_transact_nexus, preimage,
                           request_uuid):
        assert self.handlepayrequest
        self.handlepayrequest(provider_transact_nexus, preimage, request_uuid)

    ###########################################################################

    def notify_preimage(self, shared_seeds, preimage, request_reference_uuid):
        for shared_seed in shared_seeds:
            if shared_seed not in self.nexuses_by_shared_seed:
                continue
            for nexus_uuid in self.nexuses_by_shared_seed[shared_seed]:
                nexus = self.nexuses[nexus_uuid]
                nexus.notify_preimage(preimage, request_reference_uuid)
                nexus.notify_provider_info(shared_seed)

    def notify_provider_info(self, shared_seeds):
        for shared_seed in shared_seeds:
            if shared_seed not in self.nexuses_by_shared_seed:
                continue
            for nexus_uuid in self.nexuses_by_shared_seed[shared_seed]:
                nexus = self.nexuses[nexus_uuid]
                nexus.notify_provider_info(shared_seed)

    def notify_invoice(self, shared_seeds, bolt11, request_reference_uuid):
        for shared_seed in shared_seeds:
            if shared_seed not in self.nexuses_by_shared_seed:
                continue
            for nexus_uuid in self.nexuses_by_shared_seed[shared_seed]:
                nexus = self.nexuses[nexus_uuid]
                nexus.notify_invoice(bolt11, request_reference_uuid)

    def notify_error(self, shared_seeds, error_msg,
                     request_reference_uuid=None):
        for shared_seed in shared_seeds:
            if shared_seed not in self.nexuses_by_shared_seed:
                continue
            for nexus_uuid in self.nexuses_by_shared_seed[shared_seed]:
                nexus = self.nexuses[nexus_uuid]
                nexus.notify_error(error_msg,
                    request_reference_uuid=request_reference_uuid)
