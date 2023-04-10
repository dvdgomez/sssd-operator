#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""SSSD Operator Charm."""

import logging

import sssd
from ldapclient_lib import (
    CertificateAvailableEvent,
    CertificateUnavailableEvent,
    ConfigDataAvailableEvent,
    LdapClientRequires,
    SssdReadyEvent,
)
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class SSSDCharm(CharmBase):
    """SSSD Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        self.ldapclient = LdapClientRequires(self, "ldap-client")
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # LDAP Client Lib Integrations
        self.framework.observe(
            self.ldapclient.on.certificate_available,
            self._on_certificate_available,
        )
        self.framework.observe(
            self.ldapclient.on.certificate_unavailable,
            self._on_certificate_unavailable,
        )
        self.framework.observe(
            self.ldapclient.on.config_data_available,
            self._on_config_data_available,
        )
        self.framework.observe(
            self.ldapclient.on.sssd_ready,
            self._on_sssd_ready,
        )

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

    def _on_certificate_unavailable(self, event: CertificateUnavailableEvent):
        """Handle certificate-unavailable event."""
        self.unit.status = BlockedStatus("CA Certificate not available")

    def _on_certificate_available(self, event: CertificateAvailableEvent):
        """Handle certificate-available event."""
        try:
            sssd.save_ca_cert(event.ca_cert)
        except Exception:
            self.unit.status = BlockedStatus("CA Certificate secret transfer failed")

    def _on_config_data_available(self, event: ConfigDataAvailableEvent):
        """Handle certificate-available event."""
        sssd.save_conf(
            event.basedn,
            event.domain,
            event.ldap_uri,
            event.ldbd_content,
            event.lp_content,
        )
        self.unit.status = ActiveStatus("SSSD Active")

    def _on_sssd_ready(self, event: SssdReadyEvent):
        """Handle sssd-ready event."""
        sssd.restart()
        if not sssd.running:
            logger.error("Failed to start sssd")
            self.unit.status = BlockedStatus("SSSD failed to run")


if __name__ == "__main__":  # pragma: nocover
    main(SSSDCharm)
