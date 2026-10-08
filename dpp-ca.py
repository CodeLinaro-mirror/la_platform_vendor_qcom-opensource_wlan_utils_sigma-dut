#!/usr/bin/env python3
#
# Sigma Control API DUT (DPP CA)
# Copyright (c) 2020, The Linux Foundation
# All Rights Reserved.
# Licensed under the Clear BSD license. See README for more details.

import base64
import datetime
import os
import subprocess
import sys

from cryptography import x509
# The explicit default_backend() arguments below are unnecessary with
# cryptography >= 3.1, but are still required by older versions.
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

def dpp_authority_key_identifier(cacert):
    # Mimic OpenSSL's "keyid:always": use the issuer's subjectKeyIdentifier
    # when present, otherwise derive the key id from its public key.
    try:
        ski = cacert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key())

def dpp_sign_cert(cacert, cakey, csr_der):
    csr = x509.load_der_x509_csr(csr_der, default_backend())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(cacert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(12345)
    builder = builder.not_valid_before(now - datetime.timedelta(seconds=10))
    builder = builder.not_valid_after(now + datetime.timedelta(seconds=100000))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False)
    builder = builder.add_extension(dpp_authority_key_identifier(cacert),
                                    critical=False)
    return builder.sign(private_key=cakey, algorithm=hashes.SHA256(),
                        backend=default_backend())

def main():
    if len(sys.argv) < 2:
        print("No certificate directory path provided")
        sys.exit(-1)

    cert_dir = sys.argv[1]
    cacert_file = os.path.join(cert_dir, "dpp-ca.pem")
    cakey_file = os.path.join(cert_dir, "dpp-ca.key")
    csr_file = os.path.join(cert_dir, "dpp-ca-csr")
    cert_file = os.path.join(cert_dir, "dpp-ca-cert")
    pkcs7_file = os.path.join(cert_dir, "dpp-ca-pkcs7")
    certbag_file = os.path.join(cert_dir, "dpp-ca-certbag")

    with open(cacert_file, "rb") as f:
        cacert = x509.load_pem_x509_certificate(f.read(), default_backend())

    with open(cakey_file, "rb") as f:
        cakey = serialization.load_pem_private_key(f.read(), password=None,
                                                   backend=default_backend())

    if not os.path.exists(csr_file):
        print("No CSR file: %s" % csr_file)
        sys.exit(-1)

    with open(csr_file) as f:
        csr_b64 = f.read()

    csr = base64.b64decode(csr_b64)
    if not csr:
        print("Could not base64 decode CSR")
        sys.exit(-1)

    cert = dpp_sign_cert(cacert, cakey, csr)
    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    subprocess.check_call(['openssl', 'crl2pkcs7', '-nocrl',
                           '-certfile', cert_file,
                           '-certfile', cacert_file,
                           '-outform', 'DER', '-out', pkcs7_file])

    with open(pkcs7_file, 'rb') as f:
        pkcs7_der = f.read()
        certbag = base64.b64encode(pkcs7_der)
    with open(certbag_file, 'wb') as f:
        f.write(certbag)

if __name__ == "__main__":
    main()
