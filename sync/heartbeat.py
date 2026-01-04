import asyncio
import logging

logger = logging.getLogger(__name__)


async def heartbeat_loop(interval: float = 5.0):
    logger.info("Heartbeat loop started (interval=%.1f)", interval)
    while True:
        # TODO: broadcast a heartbeat frame built with common.protocol
        logger.info("Heartbeat: sending ping")
        await asyncio.sleep(interval)


def main():
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(heartbeat_loop(5.0))
    except KeyboardInterrupt:
        logger.info("Heartbeat stopped by user")


if __name__ == "__main__":
    main()
