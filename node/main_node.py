from common.transport import BLETransport
import time


def run_node():
    transport = BLETransport(adapter_index=1)

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
                print("Connection established!")

        time.sleep(5)  


if __name__ == "__main__":
    run_node()
