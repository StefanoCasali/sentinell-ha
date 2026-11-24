import logging
import threading

from . import __version__, config
from .engine import Engine
from .server import serve
from .store import Store


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger(__name__).info("Sentinella %s", __version__)
    engine = Engine(Store(config.DATA_DIR), config.load_options())
    threading.Thread(target=engine.run_forever, name="scheduler", daemon=True).start()
    threading.Thread(target=engine.republish_forever, name="republish", daemon=True).start()
    threading.Thread(target=engine.health_forever, name="health", daemon=True).start()
    serve(engine)


if __name__ == "__main__":
    main()
