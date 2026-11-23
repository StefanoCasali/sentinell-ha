"""Avvio in sviluppo, fuori da Home Assistant: http://127.0.0.1:8099

Lo stato e le opzioni stanno in .devdata/ (options.json ha lo stesso formato
delle opzioni dell'add-on). Senza l'opzione 'networks' viene scansionata la
rete a cui è collegato questo computer.
"""

import os
from pathlib import Path

os.environ.setdefault("SENTINELLA_DEV", "1")
os.environ.setdefault("SENTINELLA_DATA", str(Path(__file__).parent / ".devdata"))

from sentinella.__main__ import main  # noqa: E402

main()
