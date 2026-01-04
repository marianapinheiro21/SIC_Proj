# this abstract the use of simpleBLE for the other modules
import simplepyble
import struct

# Unique Project UUID to filter other Bluetooth devices
SERVICE_UUID = "12345678-1234-5678-1234-567812345678"


class BLETransport:
    def __init__(self, adapter_index=0):
        adapters = simplepyble.Adapter.get_adapters()
        self.adapter = adapters[adapter_index]
        self.selected_device = None

    def start_advertising(self, nid, hops):
        """
        The Peripheral (Sink or Node providing downlink) broadcasts its status.
        Manufacturer data: [NID (16 bytes)][Hops (1 byte signed)]
        """
        peripheral = simplepyble.Peripheral(self.adapter)
        # Convert NID string to bytes and Hops to signed char
        payload = nid.encode() + struct.pack('b', hops)

        peripheral.advertise_start(SERVICE_UUID, payload)
        return peripheral

    def scan_for_uplink(self):
        """
        The Central (Node looking for Sink) scans for the lowest hop count.
        """
        self.adapter.scan_for(2000)  # Scan for 2 seconds
        found_devices = self.adapter.scan_get_results()

        best_uplink = None
        min_hops = float('inf')

        for device in found_devices:
            # Check if our Service UUID is present
            if SERVICE_UUID in device.services():
                # Extract hops from manufacturer data (last byte)
                data = device.manufacturer_data()
                current_hops = struct.unpack('b', data[-1:])[0]

            # Lazy approach: find the lowest, but don't switch if already connected
            if 0 <= current_hops < min_hops:
                min_hops = current_hops
                best_uplink = device

        return best_uplink
