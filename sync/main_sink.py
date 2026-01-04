from common.transport import BLETransport


def run_sink():
    # The value below correspond to my machine but it will work
    # on other machines since is getting from the array of the system
    # Controller 1: E0:D3:62:D6:EE:14 (index 0)
    transport = BLETransport(adapter_index=0)
    sink_nid = "SINK_0000000001"  # Simplified 128-bit NID

    print(f"Sink {sink_nid} starting advertisement with hops=0...")
    peripheral = transport.start_advertising(sink_nid, 0)

    # Keep the advertisement alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        peripheral.advertise_stop()


if __name__ == "__main__":
    run_sink()
