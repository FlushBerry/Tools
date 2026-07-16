#run before: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

import http.server
import ssl

# Configuration
HOST = "localhost"
PORT = 4443

# Handler pour servir les fichiers
handler = http.server.SimpleHTTPRequestHandler

# Création du serveur
httpd = http.server.HTTPServer((HOST, PORT), handler)

# Contexte SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Wrap du socket
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Serveur HTTPS démarré sur https://{HOST}:{PORT}")
httpd.serve_forever()
