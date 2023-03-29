#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""SSSD Operator Charm."""

import logging

import sssd
from ops.charm import CharmBase, RelationChangedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class SSSDCharm(CharmBase):
    """SSSD Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Integrations
        self.framework.observe(
            self.on.sssd_ldap_relation_changed, self._on_sssd_ldap_relation_changed
        )
        # self.framework.observe(self.on.secret_changed, self._on_secret_changed)

    def _on_install(self, event):
        """Handle install event."""
        logger.debug("Install")
        if not sssd.available:
            sssd.install()

    def _on_start(self, event):
        """Handle start event."""
        logger.debug("Start")
        sssd.start()
        self.unit.status = ActiveStatus("SSSD Operator Started")

    def _on_sssd_ldap_relation_changed(self, event: RelationChangedEvent):
        """Handle sssd-ldap relation changed event."""
        # SSSD Observer gets trusted-entity secret
        trusted_entity = event.relation.data[event.app]['trusted-entity']
        secret = self.model.get_secret(id=trusted_entity)
        content = secret.get_content()
        # SSSD Configuration relation data
        auth_relation = self.model.get_relation("sssd-ldap")
        domain = auth_relation.data[event.app].get("domain")
        ldap_uri = auth_relation.data[event.app].get("ldap-uri")
        if None not in [content["ca-cert"], domain, ldap_uri]:
            try:
                sssd.save_ca_cert(content["ca-cert"])
            except Exception:
                self.unit.status = BlockedStatus("CA Certificate secret transfer failed")
            sssd.save_conf(domain, ldap_uri, content["password"])
            logger.debug("sssd-ldap relation-changed data found.")
            self.unit.status = ActiveStatus("SSSD Active")
        else:
            logger.error("sssd-ldap relation-changed data not found: ca-cert and sssd-conf.")
        if not sssd.running:
            logger.error("Failed to start sssd")
            self.unit.status = BlockedStatus("SSSD failed to run")
        


if __name__ == "__main__":  # pragma: nocover
    main(SSSDCharm)
