"""Main entrypoint for the Sink (central) node.

Contains a minimal inbox/service manager skeleton for receiving data from
nodes and coordinating the network. Extend with actual inbox/storage logic.
"""
import argparse
import logging

logger = logging.getLogger(__name__)


def run_sink():
    logger.info("Starting sink service")
    # TODO: start inbox server, heartbeat listener/dispatcher, etc.
    try:
        while True:
            # placeholder idle loop
            pass
    except KeyboardInterrupt:
        logger.info("Sink stopped by user")


def main():
    parser = argparse.ArgumentParser(description="Run Sink (main) service")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    run_sink()


if __name__ == "__main__":
    main()
