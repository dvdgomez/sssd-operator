#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Provides sssd class to control sssd."""

import logging
import subprocess

from charms.operator_libs_linux.v0 import PackageError, PackageNotFoundError, apt
from charms.operator_libs_linux.v1 import systemd
from utils.filedata import FileData

logger = logging.getLogger(__name__)

PACKAGES = ["ldap-utils", "sssd-ldap"]
SSSD = "sssd"


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
        except PackageNotFoundError as e:
            logger.error("a specified package not found in package cache or on system")
            raise e
        except PackageError as e:
            logger.error("Could not install packages.")
            raise e

    @property
    def is_enabled(self) -> bool:
        """Check enabled status of services."""
        if not systemd._systemctl("is-enabled", SSSD, quiet=True):
            return False
        return True

    @property
    def is_installed(self) -> bool:
        """Check packages are installed."""
        try:
            for pkg in PACKAGES:
                if not apt.DebianPackage.from_installed_package(pkg).present:
                    return False
        except PackageNotFoundError:
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

    def save_ca_cert(self, ca_cert):
        """Save CA certificate.

        Args:
            ca_cert (str): CA certificate.
        """
        fd = FileData(ca_cert)
        fd.save("/usr/local/share/ca-certificates/mycacert.crt")

        rc = subprocess.call(
            ["update-ca-certificates"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
        if rc != 0:
            raise Exception("Unable to update ca certificates.")

    def save_sssd_conf(self, sssd_conf):
        """Save sssd conf.

        Args:
            sssd_conf (str): SSSD configuration file.
        """
        fd = FileData(sssd_conf)
        fd.save("/etc/sssd/sssd.conf", mode=0o600, owner="root", group="root")

        systemd.service_restart(SSSD)

    def start(self) -> None:
        """Start services."""
        systemd.service_start(SSSD)

    def stop(self) -> None:
        """Stop services."""
        systemd.service_stop(SSSD)
