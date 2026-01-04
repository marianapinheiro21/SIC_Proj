from common.transport import BLETransport


def run_sink():
    transport = BLETransport(adapter_index=0)
    sink_nid = "SINK_0000000001"  # Simplified 128-bit NID

    print(f"Sink {sink_nid} starting advertisement with hops=0...")
    peripheral = transport.start_advertising(sink_nid, 0)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        peripheral.advertise_stop()


if __name__ == "__main__":
    run_sink()
