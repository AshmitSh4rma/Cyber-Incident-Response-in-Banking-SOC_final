"""
Pytest bootstrap for the SOC pipeline.

Several layers were written to be run from inside their own directory and use
bare imports (`from response_layer.models import ...`, `from ai_orchestrator
import ...`). Rather than rewrite every module, put those package roots on
sys.path so the suite collects cleanly from the repository root.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

_EXTRA_PATHS = [
    ROOT,
    os.path.join(ROOT, "layer_6_response"),
    os.path.join(ROOT, "layer_4_ai_analysis"),
    os.path.join(ROOT, "layer_2_detection"),
]

for _path in _EXTRA_PATHS:
    if os.path.isdir(_path) and _path not in sys.path:
        sys.path.insert(0, _path)
