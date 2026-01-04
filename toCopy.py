import secrets
import queue
import subprocess
import os
from datetime import datetime, timedelta, UTC
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from bleak import BleakScanner, BleakClient
from gi.repository import GLib
import dbus.mainloop.glib
import dbus.service
import dbus
import time
import asyncio
import threading
import sys

# Full implementation of Infra/BLE sanity + Central (Bleak) for the Bluetooth-based secure ad-hoc network project.
# This script implements a complete IoT node that can act as both Peripheral (GATT Server using BlueZ D-Bus) and Central (using Bleak).
# It ensures dongle/BlueZ setup, scans/connects/reconnects to uplink.
# Designed to integrate with other parts:
# - Peripheral/GATT server: Custom GATT service for data plane (write + notify), accepts multiple downlinks (clients), multiplexes frames.
# - Security: Placeholder for CA + X.509 certs, mutual auth handshake, session key derivation, MAC + anti-replay (per link).
# - Routing: Placeholder for signed heartbeats, flooding downlinks, forwarding tables, Inbox for messages to Sink.
#
# Assumptions:
# - Bluetooth 5.3 dongle is attached as 'hci0' (check with `bluetoothctl list` or `hciconfig`).
# - Use `sudo hciconfig hci0 up` if needed.
# - For VMs, ensure USB passthrough for the dongle.
# - Custom UUIDs for service and characteristic (can be changed).
# - Run as root or with sudo for BlueZ access.
# - Install dependencies: pip install bleak pydbus dbus-python
# - For security, uses cryptography library (pip install cryptography) - placeholders implemented.
# - Heartbeats: Periodic signed messages for routing (placeholders).
# - Multiplex: Frames have header (src, dest, type, seq) for routing/filtering.
# - To run as Sink: Set is_sink=True (no central/uplink).
# - README and ZIP packaging instructions at the end.


# Custom UUIDs for the project (data plane service)
SERVICE_UUID = '12345678-1234-5678-1234-56789abcdef0'
CHAR_UUID = '12345678-1234-5678-1234-56789abcdef1'

# Frame types for multiplexing
FRAME_TYPE_HEARTBEAT = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_HANDSHAKE_CERT = 0x10
FRAME_TYPE_HANDSHAKE_DH = 0x11
FRAME_TYPE_HANDSHAKE_AUTH = 0x12

# Node ID (unique, e.g., from cert or MAC)
NODE_ID = secrets.token_hex(4)  # Placeholder, replace with cert-based NID

# Generate a demo self-signed CA (for testing only - no real trust)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_subject = x509.Name([
    x509.NameAttribute(x509.NameOID.COMMON_NAME, "Demo Project CA"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "SIC Project")
])
CA_CERT = x509.CertificateBuilder().subject_name(ca_subject)\
    .issuer_name(ca_subject)\
    .public_key(ca_key.public_key())\
    .serial_number(x509.random_serial_number())\
    .not_valid_before(datetime.now(UTC))\
    .not_valid_after(datetime.now(UTC) + timedelta(days=365))\
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
    .sign(ca_key, hashes.SHA256())

# Node private key and certificate (signed by our demo CA)
NODE_KEY = ec.generate_private_key(ec.SECP256R1())
node_subject = x509.Name([
    x509.NameAttribute(x509.NameOID.COMMON_NAME, f"Node {NODE_ID}")
])
NODE_CERT = x509.CertificateBuilder().subject_name(node_subject)\
    .issuer_name(CA_CERT.subject)\
    .public_key(NODE_KEY.public_key())\
    .serial_number(x509.random_serial_number())\
    .not_valid_before(datetime.now(UTC))\
    .not_valid_after(datetime.now(UTC) + timedelta(days=365))\
    .sign(ca_key, hashes.SHA256())  # Signed by demo CA private key

# Security params
NONCE_SIZE = 12
MAC_SIZE = 16
SEQ_START = 0

# Routing
hop_count = 0  # To Sink
forwarding_table = {}  # dest: next_hop_client_path
inbox = queue.Queue()  # Messages to Sink

# BLE Sanity Check


def check_ble_infra(adapter='hci0'):
    """Ensure dongle/BlueZ is ready."""
    try:
        output = subprocess.check_output(['hciconfig', adapter])
        if b'UP' not in output:
            subprocess.run(['sudo', 'hciconfig', adapter, 'up'], check=True)
        print(f"Adapter {adapter} is up.")
        return True
    except Exception as e:
        print(f"BLE infra check failed: {e}")
        return False


# Peripheral (GATT Server) - Adapted from gatt_server.py
BLUEZ_SERVICE_NAME = 'org.bluez'
GATT_MANAGER_IFACE = 'org.bluez.GattManager1'
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
GATT_SERVICE_IFACE = 'org.bluez.GattService1'
GATT_CHARACTERISTIC_IFACE = 'org.bluez.GattCharacteristic1'
GATT_DESC_IFACE = 'org.bluez.GattDescriptor1'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'


class InvalidArgsException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'


class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = '/'
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)
        self.add_service(ChatService(bus, 0))

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE)
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            chrcs = service.get_characteristics()
            for chrc in chrcs:
                response[chrc.get_path()] = chrc.get_properties()
                descs = chrc.get_descriptors()
                for desc in descs:
                    response[desc.get_path()] = desc.get_properties()
        return response


class Service(dbus.service.Object):
    PATH_BASE = '/org/bluez/example/service'

    def __init__(self, bus, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_SERVICE_IFACE: {
                'UUID': self.uuid,
                'Primary': self.primary,
                'Characteristics': dbus.Array(
                    self.get_characteristic_paths(),
                    signature='o')
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_characteristics(self):
        return self.characteristics

    def get_characteristic_paths(self):
        result = []
        for chrc in self.characteristics:
            result.append(chrc.get_path())
        return result

    @dbus.service.method(DBUS_PROP_IFACE,
                         in_signature='s',
                         out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_SERVICE_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[GATT_SERVICE_IFACE]


class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + '/char' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.flags = flags
        self.service = service
        self.notifying = False
        self.descriptors = []
        self.clients = {}  # client_path: {'seq': 0, 'key': b'session_key', 'nonce': b'nonce'}
        dbus.service.Object.__init__(self, bus, self.path)
        self.add_descriptor(
            CharacteristicUserDescriptionDescriptor(bus, 0, self))

    def get_properties(self):
        return {
            GATT_CHARACTERISTIC_IFACE: {
                'Service': self.service.get_path(),
                'UUID': self.uuid,
                'Flags': self.flags,
                'Descriptors': dbus.Array(
                    self.get_descriptor_paths(),
                    signature='o')
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)

    def get_descriptors(self):
        return self.descriptors

    def get_descriptor_paths(self):
        result = []
        for desc in self.descriptors:
            result.append(desc.get_path())
        return result

    @dbus.service.method(DBUS_PROP_IFACE,
                         in_signature='s',
                         out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_CHARACTERISTIC_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[GATT_CHARACTERISTIC_IFACE]

    @dbus.service.method(GATT_CHARACTERISTIC_IFACE,
                         in_signature='a{sv}',
                         out_signature='ay')
    def ReadValue(self, options):
        print('Default ReadValue called, returning error')
        raise NotImplementedError()

    @dbus.service.method(GATT_CHARACTERISTIC_IFACE, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        data = bytes(value)
        client_path = options.get('device')
        if not client_path:
            raise InvalidArgsException('No device in options')

        # Security: Check if handshake done, else start handshake
        if client_path not in self.clients:
            self.handle_handshake(client_path, data)
            return

        # Verify MAC + anti-replay + decrypt
        session = self.clients[client_path]
        data = self.decrypt_and_verify(data, session)

        if data is None:
            return  # Invalid

        # Multiplex: Process frame
        frame = self.parse_frame(data)
        if frame['dest'] == NODE_ID:
            # For this node, e.g., config
            pass
        else:
            # Forward up (to Sink) via uplink if not Sink
            if uplink_central:
                uplink_central.send(data)  # Forward frame
            # Or add to inbox if Sink
            if is_sink:
                inbox.put(frame)

        # Update seq
        session['seq'] += 1

    def handle_handshake(self, client_path, data):
        # Placeholder for mutual auth + key derivation (Pessoa C)
        # Step 1: Client sends cert
        if data.startswith(b'CERT:'):
            client_cert = x509.load_pem_x509_certificate(data[5:])
            # Verify cert with CA
            try:
                client_pub = client_cert.public_key()
                client_pub.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                # Send back node cert
                cert_pem = NODE_CERT.public_bytes(serialization.Encoding.PEM)
                self.send(b'CERT:' + cert_pem)
                # DH for session key
                dh_priv = ec.generate_private_key(ec.SECP256R1())
                dh_pub = dh_priv.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )
                self.send(b'DH:' + dh_pub)
                # Wait for client DH pub, derive key (async or next write)
                # For demo, assume next write is DH pub from client
            except InvalidSignature:
                print("Invalid client cert")
                return

        # ... Complete handshake, derive key using HKDF
        # Assume client_dh_pub received
        shared = dh_priv.exchange(ec.ECDH(), client_dh_pub)
        session_key = HKDF(hashes.SHA256(), 32, salt=None,
                           info=b'ble-session').derive(shared)
        self.clients[client_path] = {
            'seq': SEQ_START, 'key': session_key, 'nonce': secrets.token_bytes(NONCE_SIZE)}

    def decrypt_and_verify(self, data, session):
        # AES-GCM decrypt + verify MAC, check seq
        aesgcm = AESGCM(session['key'])
        try:
            decrypted = aesgcm.decrypt(
                session['nonce'], data[:-MAC_SIZE], None)
            # Check seq in decrypted (first 4 bytes?)
            recv_seq = int.from_bytes(decrypted[:4], 'big')
            if recv_seq != session['seq'] + 1:
                raise ValueError("Replay attack")
            return decrypted[4:]
        except:
            return None

    def encrypt_and_mac(self, data, session):
        aesgcm = AESGCM(session['key'])
        seq_bytes = (session['seq'] + 1).to_bytes(4, 'big')
        to_encrypt = seq_bytes + data
        encrypted = aesgcm.encrypt(session['nonce'], to_encrypt, None)
        return encrypted  # MAC is included in GCM

    def parse_frame(self, data):
        # Placeholder: src(8), dest(8), type(1), seq(4), payload
        return {'src': data[:8], 'dest': data[8:16], 'type': data[16], 'seq': data[17:21], 'payload': data[21:]}

    @dbus.service.method(GATT_CHARACTERISTIC_IFACE)
    def StartNotify(self):
        if self.notifying:
            return
        self.notifying = True
        self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {
                               'Notifying': True}, [])

    @dbus.service.method(GATT_CHARACTERISTIC_IFACE)
    def StopNotify(self):
        if not self.notifying:
            return
        self.notifying = False
        self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {
                               'Notifying': False}, [])

    def send(self, data):
        # Send to all (flood downlink)
        self.PropertiesChanged(GATT_CHARACTERISTIC_IFACE, {
                               'Value': dbus.ByteArray(data)}, [])


class CharacteristicUserDescriptionDescriptor(dbus.service.Object):
    def __init__(self, bus, index, characteristic):
        self.path = characteristic.path + '/desc' + str(index)
        self.bus = bus
        self.uuid = '00002901-0000-1000-8000-00805f9b34fb'
        self.flags = ['read']
        self.characteristic = characteristic
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_DESC_IFACE: {
                'Characteristic': self.characteristic.get_path(),
                'UUID': self.uuid,
                'Flags': self.flags,
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE,
                         in_signature='s',
                         out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_DESC_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[GATT_DESC_IFACE]

    @dbus.service.method(GATT_DESC_IFACE,
                         in_signature='a{sv}',
                         out_signature='ay')
    def ReadValue(self, options):
        return dbus.ByteArray(b'Data Plane Char')


class ChatService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, SERVICE_UUID, True)
        self.add_characteristic(ChatCharacteristic(bus, 0, self))


class ChatCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        Characteristic.__init__(
            self, bus, index,
            CHAR_UUID,
            ['read', 'write', 'notify'],
            service)

    def ReadValue(self, options):
        return dbus.ByteArray(b'')


class Advertisement(dbus.service.Object):
    PATH_BASE = '/org/bluez/example/advertisement'

    def __init__(self, bus, index):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.type = 'peripheral'
        self.service_uuids = dbus.Array([SERVICE_UUID], signature='s')
        self.local_name = 'IoT Node'
        self.include_tx_power = True
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        properties = dict()
        properties['Type'] = self.type
        if self.service_uuids is not None:
            properties['ServiceUUIDs'] = dbus.Array(
                self.service_uuids, signature='s')
        if self.local_name is not None:
            properties['LocalName'] = dbus.String(self.local_name)
        if self.include_tx_power:
            properties['Includes'] = dbus.Array(['tx-power'], signature='s')
        return {'org.bluez.LEAdvertisement1': properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE,
                         in_signature='s',
                         out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != 'org.bluez.LEAdvertisement1':
            raise InvalidArgsException()
        return self.get_properties()['org.bluez.LEAdvertisement1']

    @dbus.service.method('org.bluez.LEAdvertisement1', in_signature='', out_signature='')
    def Release(self):
        print('%s: Released!' % self.path)

# Central (Bleak)


class Central:
    def __init__(self, adapter='hci0'):
        self.adapter = adapter
        self.client = None
        self.uplink_address = None
        self.session = {'seq': SEQ_START, 'key': None, 'nonce': None}
        self.connected = False

    async def scan_and_connect(self):
        while True:
            try:
                print("Scanning for uplink...")
                devices = await BleakScanner.discover(adapter=self.adapter, timeout=10.0, service_uuids=[SERVICE_UUID])
                # ... rest of code
            except bleak.exc.BleakDBusError as e:
                if "InProgress" in str(e):
                    print("Scan in progress, retrying in 5s...")
                    await asyncio.sleep(5)
                else:
                    raise

    async def start_handshake(self):
        # Send cert
        cert_pem = NODE_CERT.public_bytes(serialization.Encoding.PEM)
        await self.send(b'CERT:' + cert_pem)
        # ... Continue in on_receive for responses

    async def send(self, data):
        if self.connected and self.session['key']:
            data = self.encrypt_and_mac(data, self.session)
        if self.client and self.connected:
            await self.client.write_gatt_char(CHAR_UUID, data)

    def on_disconnect(self, client):
        self.connected = False
        print("Uplink disconnected, reconnecting...")
        asyncio.create_task(self.reconnect())

    async def reconnect(self):
        while not self.connected:
            await self.scan_and_connect()
            await asyncio.sleep(5)

    async def on_receive(self, sender, data):
        if self.session['key']:
            data = self.decrypt_and_verify(data, self.session)
            if data is None:
                return
        # Handshake responses
        if data.startswith(b'CERT:'):
            # Verify server cert, send DH, etc.
            pass  # Complete handshake
        # Process frame
        frame = parse_frame(data)  # Global parse_frame
        if frame['type'] == FRAME_TYPE_HEARTBEAT:
            # Update hop_count, forwarding
            global hop_count
            hop_count = frame['payload']['hop'] + 1
            # Flood to downlinks (peripheral send)
            chat_char.send(data)  # Assume global chat_char
        elif frame['dest'] == NODE_ID:
            # Handle
            pass
        else:
            # Forward down if route
            if frame['dest'] in forwarding_table:
                # But since flood, perhaps just send
                chat_char.send(data)


# Global for peripheral char
chat_char = None


def run_peripheral(adapter='hci0'):
    global chat_char
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter_path = f"/org/bluez/{adapter}"
    adapter_obj = bus.get_object(BLUEZ_SERVICE_NAME, adapter_path)
    service_manager = dbus.Interface(adapter_obj, GATT_MANAGER_IFACE)
    adv_manager = dbus.Interface(adapter_obj, LE_ADVERTISING_MANAGER_IFACE)
    app = Application(bus)
    time.sleep(2)
    adv = Advertisement(bus, 0)
    adv_manager.RegisterAdvertisement(adv.get_path(), {}, reply_handler=lambda: print(
        "Adv registered"), error_handler=lambda e: print(f"Adv failed: {e}"))
    service_manager.RegisterApplication(app.get_path(), {}, reply_handler=lambda: print(
        "GATT registered"), error_handler=lambda e: print(f"GATT failed: {e}"))
    chat_char = app.services[0].characteristics[0]  # Global access to char
    mainloop = GLib.MainLoop()
    mainloop.run()

# Heartbeat task (Pessoa D)


async def heartbeat_task(is_sink):
    while True:
        if is_sink:
            # Create heartbeat payload: hop count = 0, timestamp, node ID
            payload = {
                'hop': 0,
                'timestamp': time.time(),
                'node_id': NODE_ID
            }
            # Serialize payload simply (for demo)
            payload_bytes = f"{payload['hop']}|{payload['timestamp']}|{
                payload['node_id']}".encode('utf-8')

            # Sign the payload
            signature = NODE_KEY.sign(
                payload_bytes,
                ec.ECDSA(hashes.SHA256())
            )

            # Create frame: src=NODE_ID, dest=broadcast, type=heartbeat, payload=sig + data
            frame = NODE_ID.encode().ljust(8) + b'broadcast'.ljust(8) + bytes([FRAME_TYPE_HEARTBEAT]) + \
                len(signature).to_bytes(4, 'big') + signature + payload_bytes

        # Send to all connected clients (flood downlink)
        if chat_char is not None and chat_char.notifying:
            chat_char.PropertiesChanged(
                GATT_CHARACTERISTIC_IFACE,
                {'Value': dbus.ByteArray(frame)},
                []
            )
        print(f"Sink sent heartbeat (hop {payload['hop']})")

    await asyncio.sleep(30)  # Every 30 seconds


def create_frame(src, dest, ftype, payload):
    return src.encode() + dest.encode() + bytes([ftype]) + SEQ_START.to_bytes(4, 'big') + payload


# Main
if __name__ == '__main__':
    if not check_ble_infra('hci0'):
        sys.exit(1)

    is_sink = len(sys.argv) > 1 and sys.argv[1] == '--sink'

    # Start peripheral in thread
    peripheral_thread = threading.Thread(
        target=run_peripheral, args=('hci0',), daemon=True)
    peripheral_thread.start()

    # Start central if not sink
    uplink_central = None if is_sink else Central('hci0')

    async def main_async():
        if not is_sink:
            await uplink_central.scan_and_connect()
        await heartbeat_task(is_sink)

    asyncio.run(main_async())
