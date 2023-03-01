#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Configure integration test run."""

from pytest import fixture
from pytest_operator.plugin import OpsTest


@fixture(scope="module")
async def sssd_charm(ops_test: OpsTest):
    """Build sssd charm to use for integration tests."""
    charm = await ops_test.build_charm(".")
    return charm
