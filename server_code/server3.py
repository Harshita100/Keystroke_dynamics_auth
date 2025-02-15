import socket
import ssl

def start_server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to all available interfaces
    server_address = ('0.0.0.0', 12345)  # Use 0.0.0.0 to allow connections from any device
    print(f"Starting server on {server_address[0]}:{server_address[1]}")
    server_socket.bind(server_address)

    # Listen for incoming connections (max 5 clients in the waiting queue)
    server_socket.listen(5)

    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")
    context.load_verify_locations(cafile="client-cert.pem")  # Trust the client's certificate
    context.verify_mode = ssl.CERT_REQUIRED  # Require client to present a certificate

    while True:
        # Wait for a connection
        print("Waiting for a connection...")
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        ssl_socket = None  # Initialize ssl_socket to None
        try:
            # Wrap the socket with SSL
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            print(f"SSL handshake complete with {client_address}")

            # Verify the client's certificate
            client_cert = ssl_socket.getpeercert()
            if client_cert:
                print("Client certificate verified:")
                print(client_cert)
            else:
                print("No client certificate provided.")

        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except ConnectionResetError:
            print(f"Client {client_address} forcibly closed the connection.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            # Clean up the connection
            if ssl_socket:
                ssl_socket.close()
            client_socket.close()  # Ensure the raw socket is closed
            print(f"Connection with {client_address} closed.")

if __name__ == "__main__":
    start_server()