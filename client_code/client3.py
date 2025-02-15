import socket
import ssl

def start_client():
    # Create a TCP/IP socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server's address and port
    server_address = ('172.16.128.179', 12345)  # Replace with the server's IP address
    print(f"Connecting to {server_address[0]}:{server_address[1]}")
    client.connect(server_address)

    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="client-cert.pem", keyfile="client-key.pem")
    context.load_verify_locations(cafile="server-cert.pem")  # Trust the server's certificate
    context.verify_mode = ssl.CERT_REQUIRED  # Require server to present a certificate

    try:
        # Wrap the socket with SSL
        ssl_socket = context.wrap_socket(client, server_hostname="ah")  # Replace with the server's hostname
        print("SSL handshake complete")

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except ConnectionResetError:
        print("Server forcibly closed the connection.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up the connection
        ssl_socket.close()
        print("Disconnected")

if __name__ == "__main__":
    start_client()