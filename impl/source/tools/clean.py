"""Remove declared build output directories only."""

import shutil
import sys
from pathlib import Path


def main(argv):
    for name in argv:
        path = Path(name)
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
