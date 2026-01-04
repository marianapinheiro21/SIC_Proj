def decrypt_and_verify(self, data, session):
    aesgcm = AESGCM(session['key'])
    try:
        decrypted = aesgcm.decrypt(
            session['nonce'], data[:-MAC_SIZE], None)
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

def handle_handshake(self, client_path, data):
    #Client sends cert
    if data.startswith(b'CERT:'):
        client_cert = x509.load_pem_x509_certificate(data[5:])
        # Verify
        try:
            client_pub = client_cert.public_key()
            client_pub.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            cert_pem = NODE_CERT.public_bytes(serialization.Encoding.PEM)
            self.send(b'CERT:' + cert_pem)

            dh_priv = ec.generate_private_key(ec.SECP256R1())
            dh_pub = dh_priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            self.send(b'DH:' + dh_pub)

        except InvalidSignature:
            print("Invalid client cert")
            return

    shared = dh_priv.exchange(ec.ECDH(), client_dh_pub)
    session_key = HKDF(hashes.SHA256(), 32, salt=None,
                        info=b'ble-session').derive(shared)
    self.clients[client_path] = {
        'seq': SEQ_START, 'key': session_key, 'nonce': secrets.token_bytes(NONCE_SIZE)}
