#!/usr/bin/env python
from __future__ import annotations

import sys

from run_public_external_validation_eval_v18b import main


if __name__ == "__main__":
    if "--version" not in sys.argv:
        sys.argv.extend(["--version", "v18c"])
    main()
