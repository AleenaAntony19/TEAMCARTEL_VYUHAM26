import numpy as np
import pytest

from shield import face, pdq
from shield.models import YUNET, SFACE

pytestmark = pytest.mark.skipif(not (YUNET.exists() and SFACE.exists()), reason="ONNX models missing")


def test_blank_face_list():
    assert face.vectors(np.zeros((300, 300, 3), dtype=np.uint8)) == []


def test_pdq_flat_gate():
    flat = np.full((256, 256, 3), 128, dtype=np.uint8)
    assert pdq.pdq_regions(flat) == []


def test_verdict_truth_table():
    assert pdq.verdict(12, None, 0.363) == "confirmed"
    assert pdq.verdict(40, 0.40, 0.363) == "confirmed"
    assert pdq.verdict(40, None, 0.363) == "possible"
    assert pdq.verdict(None, 0.30, 0.363) is None

