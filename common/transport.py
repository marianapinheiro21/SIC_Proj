import simplepyble
import struct

SERVICE_UUID = "12345678-1234-5678-1234-567812345678"


class BLETransport:
    def __init__(self, adapter_index=0):
        adapters = simplepyble.Adapter.get_adapters()
        self.adapter = adapters[adapter_index]
        self.selected_device = None

    def start_advertising(self, nid, hops):
        peripheral = simplepyble.Peripheral(self.adapter)
        payload = nid.encode() + struct.pack('b', hops)

        peripheral.advertise_start(SERVICE_UUID, payload)
        return peripheral

    def scan_for_uplink(self):
        self.adapter.scan_for(2000) 
        found_devices = self.adapter.scan_get_results()

        best_uplink = None
        min_hops = float('inf')

        for device in found_devices:
            if SERVICE_UUID in device.services():
                data = device.manufacturer_data()
                current_hops = struct.unpack('b', data[-1:])[0]

            if 0 <= current_hops < min_hops:
                min_hops = current_hops
                best_uplink = device

        return best_uplink
