#!/usr/bin/env python3
"""
scripts/run_simple_site.py
===========================
A simple HTTP (Port 80) and HTTPS (Port 443) web server for testing NIDS packet capture.

Usage:
  1. Generate self-signed certs (if not already present):
     openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
  2. Run with root privileges (required for ports 80 & 443):
     sudo python3 scripts/run_simple_site.py
"""

import os
import sys
import ssl
import subprocess
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = f"""<!DOCTYPE html>
<html>
<head><title>NIDS Test Site</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px;">
    <h1>🛡️ NIDS Test Site (Ports 80 & 443)</h1>
    <p>Serving request on port <strong>{self.server.server_port}</strong></p>
    <p>Client IP: {self.client_address[0]}:{self.client_address[1]}</p>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

def ensure_ssl_certs(cert_file="cert.pem", key_file="key.pem"):
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print("🔑 Generating self-signed SSL certificate for HTTPS (port 443)...")
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes", "-subj", "/CN=localhost"
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("✓ Generated cert.pem and key.pem")
        except Exception as e:
            print(f"❌ Failed to generate SSL certs via openssl: {e}")
            sys.exit(1)

def run_http(port=80):
    try:
        httpd = HTTPServer(("0.0.0.0", port), CustomHandler)
        print(f"🌐 HTTP Server active on http://0.0.0.0:{port}")
        httpd.serve_forever()
    except PermissionError:
        print(f"❌ Permission denied binding to port {port}. Run with sudo!")
        sys.exit(1)
    except Exception as e:
        print(f"❌ HTTP Server error on port {port}: {e}")

def run_https(port=443, cert_file="cert.pem", key_file="key.pem"):
    ensure_ssl_certs(cert_file, key_file)
    try:
        httpd = HTTPServer(("0.0.0.0", port), CustomHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"🔒 HTTPS Server active on https://0.0.0.0:{port}")
        httpd.serve_forever()
    except PermissionError:
        print(f"❌ Permission denied binding to port {port}. Run with sudo!")
        sys.exit(1)
    except Exception as e:
        print(f"❌ HTTPS Server error on port {port}: {e}")

def main():
    print("=" * 60)
    print("  Simple HTTP & HTTPS Test Server for NIDS Testing")
    print("=" * 60)
    t1 = threading.Thread(target=run_http, args=(80,), daemon=True)
    t2 = threading.Thread(target=run_https, args=(443,), daemon=True)
    t1.start()
    t2.start()
    print("Press Ctrl+C to stop servers.\n")
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\nStopping web servers.")

if __name__ == "__main__":
    main()
