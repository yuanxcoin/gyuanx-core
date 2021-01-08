#!/usr/bin/python3

import pytest
from gnode_network import net, alice, bob, mike, chuck, chuck_double_spend

def pytest_addoption(parser):
    parser.addoption("--binary-dir", default="../../build/bin", action="store")

@pytest.fixture(scope="session")
def binary_dir(request):
    return request.config.getoption('--binary-dir')
