#this file is suppose to act as the CA tool for generating the CA.pem
NODE_ID = secrets.token_hex(4)  

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
