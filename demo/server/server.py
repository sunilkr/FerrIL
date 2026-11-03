"""
FerrIL Demo — TLS Server

A minimal TLS server that pairs with DemoTarget.exe. It:
  1. Generates a self-signed certificate on first run (saved to server.crt / server.key)
  2. Listens for TLS connections on a configurable port
  3. Reads the length-prefixed encrypted messages sent by CertPinning.cs
  4. Prints the certificate thumbprint so you can update DemoTarget if needed

Protocol (matches CertPinning.cs):
  Client sends: [4 bytes LE int32 = N] [N bytes = encrypted payload]
  Server sends: [4 bytes LE int32 = M] [M bytes = response]

Usage:
  python server.py                     # listen on 0.0.0.0:4443
  python server.py --port 8443         # listen on 0.0.0.0:8443
  python server.py --host 127.0.0.1    # listen on localhost only
  python server.py --regen             # regenerate the self-signed cert

Demo workflow:
  Terminal 1:  python demo/server.py --port 4443
  Terminal 2:  profile.exe -p ssl_unpin.dll demo\\build\\DemoTarget.exe 127.0.0.1 4443

  Without ssl_unpin, the client rejects the server cert (thumbprint mismatch).
  With ssl_unpin, the pinning check is bypassed and the TLS handshake succeeds.
"""

import argparse
import datetime
import hashlib
import os
import socket
import ssl
import struct
import subprocess
import sys
import textwrap

# Ensure print output is flushed immediately (visible when piped/backgrounded)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(SCRIPT_DIR, "server.crt")
KEY_FILE = os.path.join(SCRIPT_DIR, "server.key")


def generate_self_signed_cert():
    """Generate a self-signed certificate using the ssl module's built-in helpers,
    falling back to openssl CLI if available."""

    print("[server] Generating self-signed certificate...")

    # Try openssl CLI first (more control over output)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", KEY_FILE,
                "-out", CERT_FILE,
                "-days", "365",
                "-nodes",
                "-subj", "/CN=FerrIL Demo Server/O=FerrIL/OU=Demo",
            ],
            check=True,
            capture_output=True,
        )
        print("[server] Certificate generated via openssl CLI")
        return
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # Fallback: use Python's built-in (requires 3.10+ _ssl or cryptography)
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "FerrIL Demo Server"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FerrIL"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Demo"),
        ])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("[server] Certificate generated via cryptography library")
        return
    except ImportError:
        pass

    print("[server] ERROR: Cannot generate certificate.")
    print("[server] Install 'cryptography' package or ensure 'openssl' is on PATH:")
    print("[server]   pip install cryptography")
    sys.exit(1)


def get_cert_thumbprint():
    """Compute the SHA-1 thumbprint of the server certificate (matches .NET GetCertHashString())."""
    with open(CERT_FILE, "rb") as f:
        pem_data = f.read()

    # Extract DER from PEM
    from base64 import b64decode
    lines = pem_data.decode("ascii").strip().splitlines()
    b64 = "".join(l for l in lines if not l.startswith("-----"))
    der = b64decode(b64)

    return hashlib.sha1(der).hexdigest().upper()


def recv_exact(conn, n):
    """Read exactly n bytes from a socket/SSL connection."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def decrypt_payload(ciphertext):
    """Attempt to AES-CBC decrypt the payload using the demo's hardcoded key/IV."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        key = b"DemoAesKey!16byt"
        iv  = b"InitVector!16byt"

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode("utf-8")
    except ImportError:
        return None
    except Exception:
        return None


def handle_client(conn, addr):
    """Handle one TLS client connection using the length-prefixed protocol."""
    print("[server] Client connected: {}:{}".format(addr[0], addr[1]))

    try:
        # Read 4-byte LE length prefix
        header = recv_exact(conn, 4)
        if header is None:
            print("[server] Client disconnected before sending data")
            return

        msg_len = struct.unpack("<i", header)[0]
        print("[server] Incoming message: {} bytes".format(msg_len))

        if msg_len <= 0 or msg_len > 1024 * 1024:
            print("[server] Invalid message length: {}".format(msg_len))
            return

        # Read the encrypted payload
        payload = recv_exact(conn, msg_len)
        if payload is None:
            print("[server] Client disconnected during payload read")
            return

        print("[server] Received {} bytes of encrypted data:".format(len(payload)))
        # Print hex dump (up to 256 bytes)
        hex_str = " ".join("{:02X}".format(b) for b in payload[:256])
        for line in textwrap.wrap(hex_str, width=48):
            print("[server]   {}".format(line))
        if len(payload) > 256:
            print("[server]   ... ({} more bytes)".format(len(payload) - 256))

        # Attempt decryption with the demo's AES key
        plaintext = decrypt_payload(payload)
        if plaintext is not None:
            print("[server] Decrypted beacon: \"{}\"".format(plaintext))
            ack_msg = "ACK{{{}}}".format(plaintext)
        else:
            print("[server] (Could not decrypt — install 'cryptography' for auto-decrypt)")
            ack_msg = "ACK"

        # Send length-prefixed ACK response
        ack_bytes = ack_msg.encode("utf-8")
        conn.sendall(struct.pack("<i", len(ack_bytes)))
        conn.sendall(ack_bytes)
        print("[server] Sent response: {}".format(ack_msg))

    except ssl.SSLError as e:
        print("[server] SSL error: {}".format(e))
    except ConnectionResetError:
        print("[server] Client reset the connection")
    except Exception as e:
        print("[server] Error handling client: {}".format(e))
    finally:
        conn.close()
        print("[server] Connection closed")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="FerrIL Demo TLS Server — pairs with DemoTarget.exe")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4443,
                        help="Listen port (default: 4443)")
    parser.add_argument("--regen", action="store_true",
                        help="Regenerate the self-signed certificate")
    args = parser.parse_args()

    # Generate cert if needed
    if args.regen or not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        generate_self_signed_cert()

    thumbprint = get_cert_thumbprint()

    print()
    print("=" * 60)
    print("  FerrIL Demo TLS Server")
    print("=" * 60)
    print()
    print("  Certificate : {}".format(CERT_FILE))
    print("  Thumbprint  : {}".format(thumbprint))
    print("  Listening   : {}:{}".format(args.host, args.port))
    print()
    print("  To update the pinned thumbprint in DemoTarget,")
    print("  set PinnedThumbprint in CertPinning.cs to:")
    print("    \"{}\"".format(thumbprint))
    print()
    print("  Or bypass pinning with the profiler:")
    print("    profile.exe -p ssl_unpin.dll demo\\build\\DemoTarget.exe {} {}".format(
        "127.0.0.1" if args.host == "0.0.0.0" else args.host, args.port))
    print()
    print("=" * 60)
    print()

    # Set up TLS context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    # .NET Framework 4.0 defaults to TLS 1.0 but can negotiate higher.
    # Use TLS 1.2 as the minimum — .NET 4.0 on modern Windows supports it.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Create and bind the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(5)

    # A short timeout lets accept() yield periodically so Ctrl+C is
    # processed on Windows (blocking accept swallows KeyboardInterrupt).
    sock.settimeout(1.0)

    print("[server] Waiting for connections... (Ctrl+C to stop)")
    print()

    try:
        while True:
            try:
                client_sock, addr = sock.accept()
            except socket.timeout:
                continue
            try:
                tls_conn = ctx.wrap_socket(client_sock, server_side=True)
                handle_client(tls_conn, addr)
            except ssl.SSLError as e:
                print("[server] TLS handshake failed from {}:{} — {}".format(
                    addr[0], addr[1], e))
                print("[server] (Expected without ssl_unpin — client rejects our cert)")
                print()
                client_sock.close()
    except KeyboardInterrupt:
        print("\n[server] Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
