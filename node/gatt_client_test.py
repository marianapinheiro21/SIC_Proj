from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Optional

from bleak import BleakClient, BleakScanner

from common.protocol import SERVICE_UUID, CHAR_UUID

log = logging.getLogger("gatt_client_test")


def _on_notify(sender: int, data: bytearray):
    log.info("NOTIFY from handle=0x%04x (%d bytes): %r", sender, len(data), bytes(data)[:120])


async def find_device(name: Optional[str], address: Optional[str], timeout: float = 10.0):
    if address:
        log.info("Using address=%s", address)
        return address

    log.info("Scanning for %.1fs (service filter=%s name filter=%r)...", timeout, SERVICE_UUID, name)

    def matcher(d, ad):
        if name and (d.name != name):
            return False
        suuids = (ad.service_uuids or [])
        return SERVICE_UUID.lower() in [s.lower() for s in suuids]

    device = await BleakScanner.find_device_by_filter(matcher, timeout=timeout)
    if not device:
        return None
    return device.address


async def main_async(name: Optional[str], address: Optional[str], msg: str):
    addr = await find_device(name, address)
    if not addr:
        raise SystemExit("Device not found")

    log.info("Connecting to %s ...", addr)
    async with BleakClient(addr) as client:
        log.info("Connected. Subscribing to notifications on %s", CHAR_UUID)
        await client.start_notify(CHAR_UUID, _on_notify)

        payload = msg.encode("utf-8")
        log.info("WRITE %d bytes to %s: %r", len(payload), CHAR_UUID, payload)

        await client.write_gatt_char(CHAR_UUID, payload, response=False)

        await asyncio.sleep(2)

        log.info("Done. (Ctrl+C to exit earlier)")
        await client.stop_notify(CHAR_UUID)


def main():
    parser = argparse.ArgumentParser(description="Project GATT client test (write + notify).")
    parser.add_argument("--name", default=None, help="Peripheral name to match (optional)")
    parser.add_argument("--address", default=None, help="Peripheral BLE address (skips scanning)")
    parser.add_argument("--msg", default="hello", help="Message to write")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))
    asyncio.run(main_async(args.name, args.address, args.msg))


if __name__ == "__main__":
    main()
