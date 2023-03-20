#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""SSSD Operator Charm."""

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus
from sssd import SSSD

logger = logging.getLogger(__name__)


class SSSDCharm(CharmBase):
    """SSSD Charm."""

    def __init__(self, *args):
        """Init observe events and sssd."""
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Integrations
        self.framework.observe(
            self.on.sssd_ldap_relation_changed, self._on_sssd_ldap_relation_changed
        )
        # Client Manager
        self.sssd = SSSD()

    def _on_install(self, event):
        """Handle install event."""
        logger.info("Install")
        if not self.sssd.is_installed:
            self.sssd.install()

    def _on_start(self, event):
        """Handle start event."""
        logger.info("Start")
        self.sssd.start()
        self.unit.status = ActiveStatus("SSSD Operator Started")

    def _on_sssd_ldap_relation_changed(self, event):
        """Handle sssd-ldap relation changed event."""
        auth_relation = self.model.get_relation("sssd-ldap")
        ca_cert = auth_relation.data[event.app].get("ca-cert")
        sssd_conf = auth_relation.data[event.app].get("sssd-conf")
        if None not in [ca_cert, sssd_conf]:
            try:
                self.sssd.save_ca_cert(ca_cert)
            except Exception:
                self.unit.status = BlockedStatus("CA Certificate transfer failed")
            self.sssd.save_conf(sssd_conf)
            logger.info("sssd-ldap relation-changed data found.")
        else:
            logger.info("sssd-ldap relation-changed data not found: ca-cert and sssd-conf.")
        if not self.sssd.is_running:
            logger.error("Failed to start sssd")


if __name__ == "__main__":  # pragma: nocover
    main(SSSDCharm)
