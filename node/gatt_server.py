# node/gatt_server.py
from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Awaitable, Callable, Optional

from bluez_peripheral.util import Adapter, get_message_bus
from bluez_peripheral.advert import Advertisement, AdvertisingIncludes

from bluez_peripheral.agent import NoIoAgent
from bluez_peripheral.gatt.service import Service
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags as CharFlags

from common.protocol import SERVICE_UUID, CHAR_UUID


log = logging.getLogger("gatt_server")

class DataPlaneService(Service):
    """
    Single service + single characteristic used as the "data plane":
      - centrals WRITE frames to this characteristic
      - server NOTIFY frames back (broadcast to subscribed centrals)
    """

    def __init__(
        self,
        on_rx: Optional[Callable[[bytes], Awaitable[None]]] = None,
    ):
        # Primary service
        super().__init__(SERVICE_UUID, True)
        self._last_value: bytes = b""
        self._on_rx = on_rx

    @characteristic(CHAR_UUID, CharFlags.READ | CharFlags.WRITE | CharFlags.NOTIFY)
    def dataplane(self, options):
        # READ returns the last notified value (handy for debugging)
        return self._last_value

    @dataplane.setter
    def dataplane(self, value: bytes, options):
        """
        Called by BlueZ when a central writes to the characteristic.
        NOTE: this setter is sync; if you need async work, schedule it.
        """
        self._last_value = bytes(value)
        log.info("RX write (%d bytes): %r", len(self._last_value), self._last_value[:80])

        # Echo back immediately (useful for your first BLE test)
        # This NOTIFY goes to all subscribed centrals.
        self.dataplane.changed(self._last_value)

        if self._on_rx is not None:
            # Schedule async processing without blocking dbus callbacks
            asyncio.get_event_loop().create_task(self._on_rx(self._last_value))

    def notify(self, data: bytes) -> None:
        """
        Push a NOTIFY update to subscribed centrals.
        """
        self._last_value = bytes(data)
        self.dataplane.changed(self._last_value)


async def run_server(name: str, advertise_seconds: int) -> None:
    bus = await get_message_bus()

    service = DataPlaneService()
    await service.register(bus)

    # Agent required for pairing flows (even if you don't pair right now)
    agent = NoIoAgent()
    await agent.register(bus)

    adapter = await Adapter.get_first(bus)

    # Advertise your service UUID so clients can filter by it
    advert = Advertisement(name, [SERVICE_UUID], 0x0000, advertise_seconds)
    
    #advert = Advertisement( local_name=name, 
    #                   service_uuids=[SERVICE_UUID], 
    #                   appearance=0x0000, 
    #                   timeout=advertise_seconds, 
    #                   includes=AdvertisingIncludes.NONE
    #                   )

    await advert.register(bus, adapter)

    log.info("Advertising as %r with service=%s char=%s", name, SERVICE_UUID, CHAR_UUID)
    log.info("Waiting for centrals... (Ctrl+C to stop)")

    try:
        while True:
            # IMPORTANT: yield to asyncio so notifications work properly
            await asyncio.sleep(1)
    finally:
        # Best-effort cleanup
        try:
            await advert.unregister()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Project GATT Peripheral (data plane).")
    parser.add_argument("--name", default="IoT-Node", help="BLE local name to advertise")
    parser.add_argument(
        "--advertise-seconds",
        type=int,
        default=0,
        help="Advertisement lifetime in seconds (0 often means 'no timeout' depending on BlueZ).",
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    # bluez-peripheral docs note you may need:
    # - to be root for agent/advert registration, OR
    # - to be in bluetooth group + proper dbus permissions
    #asyncio.run(run_server(args.name, args.advertise_seconds))
    
    try:
        asyncio.run(run_server(args.name, args.advertise_seconds))
    except KeyboardInterrupt:
        log.info("Server stopped by user")


if __name__ == "__main__":
    main()
