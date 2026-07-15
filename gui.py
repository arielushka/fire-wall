from pathlib import Path
import sys

CODE_DIR = Path(__file__).resolve().parent / "code"
sys.path.insert(0, str(CODE_DIR))

from gui_app import main

if __name__ == "__main__":
    main()
