#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Provides sssd class to control sssd."""

import base64
import logging
import os
import subprocess

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

logger = logging.getLogger(__name__)


class SSSD:
    """Provide sssd charm all functionality needed."""

    def _save(self, data: str, path: str) -> None:
        """Decode base64 string and writes to path."""
        data = base64.b64decode(data.encode("utf-8"))
        with open(path, "wb") as f:
            f.write(data)

    @property
    def available(self) -> bool:
        """Check packages are installed."""
        try:
            apt.DebianPackage.from_installed_package("sssd-ldap")
            apt.DebianPackage.from_installed_package("ldap-utils")
            return True
        except apt.PackageNotFoundError as e:
            logger.debug(f"{e.message.split()[-1]} is not installed...")
            return False

    def disable(self) -> None:
        """Disable services."""
        systemd.service_pause("sssd")

    def enable(self) -> None:
        """Enable services."""
        systemd.service_resume("sssd")

    def install(self) -> None:
        """Install using charmlib apt."""
        try:
            apt.update()
            apt.add_package("ldap-utils")
            apt.add_package("sssd-ldap")
        except apt.PackageNotFoundError as e:
            logger.error("a specified package not found in package cache or on system")
            raise e
        except apt.PackageError as e:
            logger.error("Could not install packages.")
            raise e

    def remove(self) -> None:
        """Remove packages."""
        try:
            apt.remove_package("ldap-utils")
            apt.remove_package("sssd-ldap")
        except apt.PackageNotFoundError as e:
            logger.error(
                "a specified package to remove is not found in package cache or on system"
            )
            raise e

    def restart(self) -> None:
        """Restart servers/services."""
        systemd.service_restart("sssd")

    @property
    def running(self) -> bool:
        """Check running/active status of services."""
        if not systemd.service_running("sssd"):
            return False
        return True

    def save_ca_cert(self, ca_cert) -> None:
        """Save CA certificate.

        Args:
            ca_cert (str): CA certificate.
        """
        cacert_path = "/etc/ssl/certs/mycacert.crt"
        self._save(ca_cert, cacert_path)

        try:
            subprocess.run(
                ["update-ca-certificates"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"{e} Reason:\n{e.stderr}")

    def save_conf(self, sssd_conf) -> None:
        """Save sssd conf.

        Args:
            sssd_conf (str): SSSD configuration file.
        """
        sssd_conf_path = "/etc/sssd/sssd.conf"
        # Decode base64 string and writes to path
        self._save(sssd_conf, sssd_conf_path)
        # Change file ownership and permissions
        os.chown(sssd_conf_path, 0, 0)
        os.chmod(sssd_conf_path, 0o600)
        systemd.service_restart("sssd")

    def start(self) -> None:
        """Start services."""
        systemd.service_start("sssd")

    def stop(self) -> None:
        """Stop services."""
        systemd.service_stop("sssd")
