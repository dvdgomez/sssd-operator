#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Provides sssd class to control sssd."""

import logging
import subprocess

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd
from helpers import fchange, save

logger = logging.getLogger(__name__)

CACERT = "/usr/local/share/ca-certificates/mycacert.crt"
PACKAGES = ["ldap-utils", "sssd-ldap"]
SSSD = "sssd"
SSSDCONF = "/etc/sssd/sssd.conf"


class Sssd:
    """Provide sssd charm all functionality needed."""

    def disable(self) -> None:
        """Disable services."""
        systemd.service_pause(SSSD)

    def enable(self) -> None:
        """Enable services."""
        systemd.service_resume(SSSD)

    def install(self) -> None:
        """Install using charmlib apt."""
        try:
            apt.update()
            apt.add_package(PACKAGES)
        except apt.PackageNotFoundError as e:
            logger.error("a specified package not found in package cache or on system")
            raise e
        except apt.PackageError as e:
            logger.error("Could not install packages.")
            raise e

    @property
    def is_installed(self) -> bool:
        """Check packages are installed."""
        try:
            for pkg in PACKAGES:
                if not apt.DebianPackage.from_installed_package(pkg).present:
                    return False
        except apt.PackageNotFoundError:
            logger.error(f"package {pkg} is not currently installed.")
            return False
        return True

    @property
    def is_running(self) -> bool:
        """Check running/active status of services."""
        if not systemd.service_running(SSSD):
            return False
        return True

    def restart(self) -> None:
        """Restart servers/services."""
        self.stop()
        self.start()

    def save_ca_cert(self, ca_cert) -> None:
        """Save CA certificate.

        Args:
            ca_cert (str): CA certificate.
        """
        save(ca_cert, CACERT)

        rc = subprocess.call(
            ["update-ca-certificates"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
        if rc != 0:
            raise Exception("Unable to update ca certificates.")

    def save_sssd_conf(self, sssd_conf) -> None:
        """Save sssd conf.

        Args:
            sssd_conf (str): SSSD configuration file.
        """
        save(sssd_conf, SSSDCONF)
        fchange(SSSDCONF)

        systemd.service_restart(SSSD)

    def start(self) -> None:
        """Start services."""
        systemd.service_start(SSSD)

    def stop(self) -> None:
        """Stop services."""
        systemd.service_stop(SSSD)
