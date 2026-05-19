import logging
import sys

_FORMAT = "[%(asctime)s] %(levelname)-8s [%(name)s] %(message)s"
_DATE = "%Y-%m-%dT%H:%M:%S"
_CONFIGURED = False


def setup(debug: bool = False) -> None:
    """Configure the root logger with a stderr handler. Safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT, _DATE))
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger by name."""
    return logging.getLogger(name)
