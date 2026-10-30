import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def fx(tmp_path_factory):
    from demo.make_fixtures import build

    out = tmp_path_factory.mktemp("fixtures")
    return build(out)

