import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

class CaesarCipher:
    @staticmethod
    def encrypt(text, shift):
        return ''.join(
            chr((ord(char) - 32 + shift) % 95 + 32) if 32 <= ord(char) <= 126 else char
            for char in text
        )

class StartPacket:
    def __init__(self, packet_type="SS", protocol_name="RFMP", protocol_version="v1.0", cipher_type="None"):
        self.packet_type = packet_type
        self.protocol_name = protocol_name
        self.protocol_version = protocol_version
        self.cipher_type = cipher_type

    def __str__(self):
        return f"{self.packet_type},{self.cipher_type},{self.protocol_name},{self.protocol_version}"

class EncryptionPacket:
    def __init__(self, algorithm="AES", session_key=None, client_pub_key=None):
        self.packet_type = "EC"
        self.algorithm = algorithm
        self.session_key = session_key
        self.client_pub_key = client_pub_key

    def __str__(self):
        return f"{self.packet_type},{self.algorithm},{base64.b64encode(self.session_key).decode()},{self.client_pub_key}"

def send_command(sock, command_type, command, args=""):
    packet = f"{command_type},{command},{args}"
    sock.send(packet.encode("utf-8"))
    response = sock.recv(2048).decode("utf-8")
    print(f"Server Response: {response}")

def generate_rsa_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey().export_key()
    return private_key, public_key

def encrypt_session_key(session_key, server_pub_key):
    cipher_rsa = PKCS1_OAEP.new(server_pub_key)
    return cipher_rsa.encrypt(session_key)

def client_main():
    host = "127.0.0.1"
    port = 5000

    encrypt_packets = input("Would you like to encrypt packets? (yes/no): ").strip().lower()
    cipher_type = "None"
    session_key = None
    caesar_shift = None

    if encrypt_packets == "yes":
        cipher_type = input("Choose encryption type (AES, Caesar): ").strip()
        if cipher_type == "AES":
            session_key = get_random_bytes(16)  # Example 16-byte AES key
        elif cipher_type == "Caesar":
            caesar_shift = int(input("Enter Caesar cipher shift value (e.g., 3): "))

    client_private_key, client_public_key = generate_rsa_keys()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print("Connected to the server.")

        start_packet = StartPacket(cipher_type=cipher_type)
        s.send(str(start_packet).encode("utf-8"))
        print(f"Sent start packet: {start_packet}")

        response = s.recv(2048).decode("utf-8")
        print(f"Received confirm-connection packet: {response}")

        if cipher_type == "AES":
            fields = response.split(",")
            server_pub_key = RSA.import_key(base64.b64decode(fields[1]))
            encrypted_session_key = encrypt_session_key(session_key, server_pub_key)
            encryption_packet = EncryptionPacket(
                algorithm="AES",
                session_key=encrypted_session_key,
                client_pub_key=client_public_key.decode()
            )
            s.send(str(encryption_packet).encode("utf-8"))
            print(f"Sent encryption packet: {encryption_packet}")

        while True:
            command_input = input("Enter a command (or 'exit' to quit): ").strip()
            if command_input.lower() == "exit":
                s.send("End".encode("utf-8"))
                break

            command_parts = command_input.split(" ", 1)
            command = command_parts[0]
            args = command_parts[1] if len(command_parts) > 1 else ""

            if cipher_type == "Caesar" and args:
                args = CaesarCipher.encrypt(args, caesar_shift)

            send_command(s, "CM", command, args)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        s.close()
        print("Connection closed.")

if __name__ == "__main__":
    client_main()

