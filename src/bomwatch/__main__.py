"""Allow ``python -m bomwatch``."""

import sys

from bomwatch.cli import main

sys.exit(main())
