import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import main


def test_concurrency_constants_updated():
	assert main.MAX_CONCURRENT_ACCOUNTS == 10
	assert main.MAX_CONCURRENT_RUNTIME_DISCOVERY == 10
	assert main.MAX_CONCURRENT_LINUXDO_PRELOGIN == 2
