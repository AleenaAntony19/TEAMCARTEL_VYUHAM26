#!/usr/bin/env bash
# Face models (Apache-2.0, opencv_zoo). Hashes pinned: a changed upstream file fails the build.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p models
fetch() {
  [ -f "models/$1" ] || curl -fsSL -o "models/$1" "$2"
  python3 - "$1" "$3" <<'PY'
import hashlib, sys
name, want = sys.argv[1], sys.argv[2]
got = hashlib.sha256(open(f"models/{name}", "rb").read()).hexdigest()
sys.exit(0 if got == want else f"checksum mismatch for {name}: {got}")
PY
}
fetch face_detection_yunet_2023mar.onnx https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4
fetch face_recognition_sface_2021dec.onnx https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx 0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79
echo "models ok"
