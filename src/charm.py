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
            self.on.ldap_client_relation_changed, self._on_ldap_client_relation_changed
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

    def _on_ldap_client_relation_changed(self, event: RelationChangedEvent):
        """Handle ldap-client relation changed event."""
        # SSSD Observer retrieves secrets
        ca_cert = event.relation.data[event.app]["ca-cert"]
        default_bind_dn = event.relation.data[event.app]["ldap-default-bind-dn"]
        ldap_password = event.relation.data[event.app]["ldap-password"]
        cc_secret = self.model.get_secret(id=ca_cert)
        ldbd_secret = self.model.get_secret(id=default_bind_dn)
        lp_secret = self.model.get_secret(id=ldap_password)
        cc_content = cc_secret.get_content()
        ldbd_content = ldbd_secret.get_content()
        lp_content = lp_secret.get_content()
        # SSSD Configuration relation data
        auth_relation = self.model.get_relation("ldap-client")
        basedn = auth_relation.data[event.app].get("basedn")
        domain = auth_relation.data[event.app].get("domain")
        ldap_uri = auth_relation.data[event.app].get("ldap-uri")
        if None not in [
            cc_content["ca-cert"],
            ldbd_content["ldap-default-bind-dn"],
            lp_content["ldap-password"],
            basedn,
            domain,
            ldap_uri,
        ]:
            try:
                sssd.save_ca_cert(cc_content["ca-cert"])
            except Exception:
                self.unit.status = BlockedStatus("CA Certificate secret transfer failed")
            sssd.save_conf(
                basedn,
                domain,
                ldap_uri,
                ldbd_content["ldap-default-bind-dn"],
                lp_content["ldap-password"],
            )
            logger.debug("sssd-ldap relation-changed data found.")
            self.unit.status = ActiveStatus("SSSD Active")
        else:
            logger.error("sssd-ldap relation-changed data not found: ca-cert and sssd-conf.")
        if not sssd.running:
            logger.error("Failed to start sssd")
            self.unit.status = BlockedStatus("SSSD failed to run")


if __name__ == "__main__":  # pragma: nocover
    main(SSSDCharm)
