"""Enables ``python -m cleanroom ...`` as an alias for the console script."""

import sys

from cleanroom.interfaces.cli import main

if __name__ == "__main__":
    sys.exit(main())
