#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""SSSD Operator Charm."""

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus
from sssd import Sssd

logger = logging.getLogger(__name__)


class SssdCharm(CharmBase):
    """SSSD Charm."""

    def __init__(self, *args):
        """Init observe events and sssd."""
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Integrations
        self.framework.observe(
            self.on.sssd_auth_relation_changed, self._on_sssd_auth_relation_changed
        )
        # Client Manager
        self.sssd = Sssd()

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

    def _on_sssd_auth_relation_changed(self, event):
        """Handle sssd-auth relation changed event."""
        auth_relation = self.model.get_relation("sssd-auth")
        ca_cert = auth_relation.data[event.app].get("ca-cert")
        sssd_conf = auth_relation.data[event.app].get("sssd-conf")
        if None not in [ca_cert, sssd_conf]:
            self.sssd.save_ca_cert(ca_cert)
            self.sssd.save_sssd_conf(sssd_conf)
            logger.info("sssd-auth relation-changed data found.")
        else:
            logger.info("sssd-auth relation-changed data not found: ca-cert and sssd-conf.")
        if not self.sssd.is_running:
            logger.error("Failed to start sssd")


if __name__ == "__main__":  # pragma: nocover
    main(SssdCharm)
