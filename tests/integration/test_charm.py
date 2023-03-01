#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test sssd charm."""

import pytest
from pytest_operator.plugin import OpsTest

SSSD = "sssd"
SERIES = ["jammy"]


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("series", SERIES)
@pytest.mark.skip_if_deployed
async def test_deploy(ops_test: OpsTest, series: str, sssd_charm):
    """Test sssd charm deployment."""
    # Build and Deploy sssd
    await ops_test.model.deploy(
        str(await sssd_charm),
        application_name=SSSD,
        num_units=1,
        series=series,
    )
    # issuing update_status just to trigger an event
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=[SSSD], status="active", timeout=1000)
        assert ops_test.model.applications[SSSD].units[0].workload_status == "active"
