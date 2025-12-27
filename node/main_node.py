"""Main entrypoint for an IoT node device.

This file contains a minimal CLI and sensor loop stub. Replace sensor
logic and transport selection with actual implementations as needed.
"""
import argparse
import logging
import time

logger = logging.getLogger(__name__)


def read_sensor() -> float:
    """Stub: return a fake sensor reading (float)."""
    return time.time() % 100  # deterministic-ish placeholder


def run_node(poll_interval: float = 5.0):
    logger.info("Starting node with poll interval %.1fs", poll_interval)
    try:
        while True:
            val = read_sensor()
            logger.info("Sensor read: %s", val)
            # TODO: build frame via common.protocol and send over transport
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("Node stopped by user")


def main():
    parser = argparse.ArgumentParser(description="Run IoT node")
    parser.add_argument("--interval", "-i", type=float, default=5.0,
                        help="Sensor polling interval in seconds")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    run_node(args.interval)


if __name__ == "__main__":
    main()
