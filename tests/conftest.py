import pytest

from bomwatch import walk


@pytest.fixture(autouse=True)
def fresh_walk():
    walk.clear()
    yield
    walk.clear()
