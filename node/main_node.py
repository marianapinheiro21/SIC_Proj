from common.transport import BLETransport
import time


def run_node():
    # Controller 2: 4C:D5:77:E1:37:B2 (index 1)
    transport = BLETransport(adapter_index=1)

    # Varibles not used for now since not making advertisement on the IoT device
    node_nid = "NODE_0000000002"
    uplink_device = None
    hops = -1  # Start with negative hops

    while True:
        if uplink_device is None or not uplink_device.is_connected():
            print("Searching for uplink...")
            target = transport.scan_for_uplink()

            if target:
                print(f"Connecting to {target.identifier()}...")
                target.connect()
                uplink_device = target
                # Set local hops to uplink_hops + 1
                # (Logic to read manufacturer data and update local state)
                print("Connection established!")

        time.sleep(5)  # Check link liveness


if __name__ == "__main__":
    run_node()
