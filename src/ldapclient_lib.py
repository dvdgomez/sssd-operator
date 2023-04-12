# Copyright 2023 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Library for the ldap-client relation.

This library contains the Provides and Requires classes for handling the ldap-client interface.


### Provider Charm

### Requirer Charm


"""

import logging
import pathlib
import shlex
import subprocess
import zipfile

from ops.charm import (
    CharmBase,
    CharmEvents,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationJoinedEvent,
)
from ops.framework import EventBase, EventSource, Handle, Object
from ops.model import ActiveStatus, MaintenanceStatus, ModelError

logger = logging.getLogger(__name__)

"""
Events - TBD
"""

# class LdapClientProviderCharmEvents(CharmEvents):
#    """Events the LDAP Client provider can leverage."""
# No custom events necessary for the provider, just has to pass along
# information to the client.


class GlauthSnapReadyEvent(EventBase):
    """Charm Event triggered when a glauth snap is ready to start."""

    def __init__(
        self,
        handle: Handle,
    ):
        super().__init__(handle)


class CertificateAvailableEvent(EventBase):
    """Charm Event triggered when a CA certificate is available."""

    def __init__(
        self,
        handle: Handle,
        ca_cert: str,
    ):
        super().__init__(handle)
        self.ca_cert = ca_cert

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "ca_cert": self.ca_cert,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.ca_cert = snapshot["ca_cert"]


class CertificateUnavailableEvent(EventBase):
    """Charm Event triggered when a CA certificate is unavailable."""

    pass


class ConfigDataAvailableEvent(EventBase):
    """Charm Event triggered when config data is available."""

    def __init__(
        self,
        handle: Handle,
        basedn: str,
        ldap_uri: str,
        ldbd_content: str,
        lp_content: str,
    ):
        super().__init__(handle)
        self.basedn = basedn
        self.ldap_uri = ldap_uri
        self.ldbd_content = ldbd_content
        self.lp_content = lp_content

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "basedn": self.basedn,
            "ldap_uri": self.ldap_uri,
            "ldbd_content": self.ldbd_content,
            "lp_content": self.lp_content,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.basedn = snapshot["basedn"]
        self.ldap_uri = snapshot["ldap_uri"]
        self.ldbd_content = snapshot["ldbd_content"]
        self.lp_content = snapshot["lp_content"]


class ConfigDataUnavailableEvent(EventBase):
    """Charm Event triggered when config data is unavailable."""

    def __init__(
        self,
        handle: Handle,
        api_port: int,
        ldap_port: int,
    ):
        super().__init__(handle)
        self.api_port = api_port
        self.ldap_port = ldap_port

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "api_port": self.api_port,
            "ldap_port": self.ldap_port,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.api_port = snapshot["api_port"]
        self.ldap_port = snapshot["ldap_port"]


class ServerUnavailableEvent(EventBase):
    """Charm Event triggered When the LDAP server is unavailable."""

    def __init__(
        self,
        handle: Handle,
    ):
        super().__init__(handle)


class LdapReadyEvent(EventBase):
    """Charm Event triggered when LDAP is ready to start."""

    def __init__(
        self,
        handle: Handle,
    ):
        super().__init__(handle)


class LdapClientProviderCharmEvents(CharmEvents):
    """Events the LDAP Client requirer can leverage."""

    config_data_unavailable = EventSource(ConfigDataUnavailableEvent)
    glauth_snap_ready = EventSource(GlauthSnapReadyEvent)
    server_unavailable = EventSource(ServerUnavailableEvent)


class LdapClientRequirerCharmEvents(CharmEvents):
    """Events the LDAP Client requirer can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)
    certificate_unavailable = EventSource(CertificateUnavailableEvent)
    config_data_available = EventSource(ConfigDataAvailableEvent)
    config_data_unavailable = EventSource(ConfigDataUnavailableEvent)
    server_unavailable = EventSource(ServerUnavailableEvent)
    ldap_ready = EventSource(LdapReadyEvent)


class LdapClientProvides(Object):
    """Provides-side of the ldapclient integration."""

    on = LdapClientProviderCharmEvents()

    def __init__(self, charm: CharmBase, integration_name: str) -> None:
        super().__init__(charm, integration_name)
        self.framework.observe(
            charm.on[integration_name].relation_broken,
            self._on_relation_broken,
        )
        self.framework.observe(
            charm.on[integration_name].relation_joined,
            self._on_relation_joined,
        )
        self.charm = charm
        self.integration_name = integration_name

    def _get_hostname(self) -> str:
        """Get GLAuth hostname.

        Returns:
            GLAuth hostname.
        """
        hostname = subprocess.run(
            ["cat", "/etc/hostname"], capture_output=True, text=True
        ).stdout.strip()
        return hostname

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle relation-broken event.

        When the ldapclient relation is broken and emits:
        - Server unavailable event: When the ldap server can't be reached.
        """
        # Remove Obsolete Secrets
        ca_cert_secret = self.model.get_secret(label="ca-cert")
        ldbd_secret = self.model.get_secret(label="ldap-default-bind-dn")
        lp_secret = self.model.get_secret(label="ldap-password")
        ca_cert_secret.remove_all_revisions()
        ldbd_secret.remove_all_revisions()
        lp_secret.remove_all_revisions()
        self.on.server_unavailable.emit()

    def _on_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the relation is joined.

        Looks at the relation data and config values and emits:
        - config unavailable event: If the config resource is not supplied.
        - glauth snap event: When the glauth certificate, config, and key are available.
        """
        self.charm.unit.status = MaintenanceStatus("reconfiguring glauth")
        # Check model for GLAuth config resource
        try:
            resource_path = self.model.resources.fetch("config")
        except ModelError:
            logger.debug("No config resource supplied")
            resource_path = None
            self.on.config_data_unavailable.emit(
                api_port=self.model.config["api-port"], ldap_port=self.model.config["ldap-port"]
            )
        # Set config and get LDAP URI
        ldap_uri = self.set_config(
            resource_path, self.model.config["ldap-port"], self.model.config["api-port"]
        )
        # Get CA Cert and key
        ca_cert = self.load()
        # Signals glauth snap is ready to be started
        self.on.glauth_snap_ready.emit()
        cc_content = {"ca-cert": ca_cert}
        # Get Peer Secrets
        ldap_relation = self.model.get_relation("glauth")
        default_bind_dn = ldap_relation.data[self.charm.app]["ldap-default-bind-dn"]
        ldap_password = ldap_relation.data[self.charm.app]["ldap-password"]
        ldbd_secret = self.model.get_secret(id=default_bind_dn)
        lp_secret = self.model.get_secret(id=ldap_password)
        # Create Secrets
        cc_secret = self.charm.app.add_secret(cc_content, label="ca-cert")
        logger.debug("created secret %s", cc_secret)
        cc_secret.grant(event.relation)
        ldbd_secret.grant(event.relation)
        lp_secret.grant(event.relation)
        event.relation.data[self.charm.app]["ca-cert"] = cc_secret.id
        event.relation.data[self.charm.app]["ldap-default-bind-dn"] = ldbd_secret.id
        event.relation.data[self.charm.app]["ldap-password"] = lp_secret.id
        # Configuration data update
        ldap_relation = self.model.get_relation("ldap-client")
        ldap_relation.data[self.charm.app].update(
            {
                "basedn": self.model.config["ldap-search-base"],
                "ldap-uri": ldap_uri,
            }
        )
        self.charm.unit.status = ActiveStatus("glauth ready")

    def load(self) -> str:
        """Load ca-certificate from glauth snap.

        Returns:
            The ca certificate content.
        """
        cert = "/var/snap/glauth/common/etc/glauth/certs.d/glauth.crt"
        key = "/var/snap/glauth/common/etc/glauth/keys.d/glauth.key"
        if not pathlib.Path(cert).exists() and not pathlib.Path(key).exists():
            # If cert and key do not exist, create both
            subprocess.run(
                shlex.split(
                    f'openssl req -x509 -newkey rsa:4096 -keyout {key} -out {cert} -days 365 -nodes -subj "/CN={self._get_hostname()}"'
                )
            )
        content = open(cert, "r").read()
        return content

    def set_config(self, config: pathlib.Path, ldap_port: int, api_port: int) -> str:
        """Set GLAuth config resource. Create default if none found.

        Args:
            config: Resource config Path object.
            ldap_port: LDAP port for default config.
            api_port: API port for default config.


        Returns:
            LDAP URI.
        """
        ldap_uri = "ldap"
        # Create default config with no users if resource glauth.cfg not found
        if config is None:
            ldap_uri = ldap_uri + f"://{self._get_hostname()}:{ldap_port}"
        # Zip file of multiple configs
        else:
            with zipfile.ZipFile(config, "r") as zip:
                zip.extractall("/var/snap/glauth/common/etc/glauth/glauth.d/")
            ldap_uri = ldap_uri + f"s://{self._get_hostname()}:{ldap_port}"
        return ldap_uri


class LdapClientRequires(Object):
    """Requires-side of the ldapclient integration."""

    on = LdapClientRequirerCharmEvents()

    def __init__(self, charm: CharmBase, integration_name: str) -> None:
        super().__init__(charm, integration_name)
        self.framework.observe(
            charm.on[integration_name].relation_changed,
            self._on_relation_changed,
        )
        self.framework.observe(
            charm.on[integration_name].relation_broken,
            self._on_relation_broken,
        )
        self.charm = charm
        self.integration_name = integration_name

    def _on_relation_broken(self, event: RelationBrokenEvent):
        """Handle relation-broken event.

        When the ldapclient relation is broken and emits:
        - Server unavailable event: When the ldap server can't be reached.
        """
        self.on.server_unavailable.emit()

    def _on_relation_changed(self, event: RelationChangedEvent):
        """Handle relation-changed event.

        Looks at the relation data and either emits:
        - Certificate available event: When a CA certificate is available.
        - Certificate unavailable event: When a CA certificate is unavailable.
        - Configuration data available event: When configuration data is available.
        - Configuration data unavailable event: When configuration data is unavailable.
        - Ldap ready event: When cert and config are available.
        """
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
        if None not in [cc_content["ca-cert"]]:
            self.on.certificate_available.emit(ca_cert=cc_content["ca-cert"])
        # SSSD Configuration relation data
        auth_relation = self.model.get_relation("ldap-client")
        basedn = auth_relation.data[event.app].get("basedn")
        ldap_uri = auth_relation.data[event.app].get("ldap-uri")
        if None not in [
            ldbd_content["ldap-default-bind-dn"],
            lp_content["ldap-password"],
            basedn,
            ldap_uri,
        ]:
            self.on.config_data_available.emit(
                basedn=basedn,
                ldap_uri=ldap_uri,
                ldbd_content=ldbd_content["ldap-default-bind-dn"],
                lp_content=lp_content["ldap-password"],
            )
        else:
            logger.error("sssd-ldap relation-changed data not found: ca-cert and sssd-conf.")
        self.on.ldap_ready.emit()
