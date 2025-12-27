# Upon receiving a node name must generate the node_NID.crt and the node_NID.key# Node private key and certificate (signed by our demo CA)
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
