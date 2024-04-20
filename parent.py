"""This file contains parent classes."""
import sys
import random
import hashlib
import sympy
import vigenere


class Endpoint:
    """This class contains all methods needed by an endpoint"""

    

    def __init__(self, input_traffic_file, output_traffic_file, name, mode):
        self.input_traffic_file = input_traffic_file
        self.output_traffic_file = output_traffic_file
        self.priv_key = 42
        self.shared_key = 42
        self.name = name
        self.mode = mode
        self.main()

    def gen_prime(self, a = 2**16, b = 2**17):
        """Generates a random prime number between a and b"""
        primes = []
        for i in range(a, b):
            if sympy.isprime(i):
                primes.append(i)
        return random.choice(primes)

    def gen_hello_message(
        self, public_generator = 42,
        public_prime = 42, peer_pub_key = 42
        ):
        """Generates the hello message for
        the key exchange."""
        public_generator, public_prime, self_pub_key = self.pub_key_gen(public_generator, public_prime, peer_pub_key)

        return str(
            self.mode + "_HELLO::" + self.name + "::"
            + str(public_generator) + "::" + str(public_prime) + "::" + str(self_pub_key)
            )

    def gen_message(self, cipher, message_hash):
        """Generates a sendable message from a cipher and the message hash."""
        return str("MESSAGE::" + str(cipher) + "::" + str(message_hash))

    def priv_key_gen(self, public_prime):
        """This method creates the private key."""
        return random.randint(1, int(public_prime) - 1)

    def pub_key_gen(
        self, public_generator = 42,
        public_prime = 42, peer_pub_key = 42
        ):
        """This method generates the public key of the endpoint,
        if no parameters are given, it also creates the public
        prime and the public generator."""

        if public_generator == public_prime == peer_pub_key == 42:
            public_prime = self.gen_prime()
            public_generator = random.randint(2**12, int(public_prime)-1)
        self.priv_key = self.priv_key_gen(int(public_prime))
        self_pub_key = (int(public_generator)**self.priv_key)%int(public_prime)
        return public_generator, public_prime, self_pub_key

    def shared_key_gen(self, public_prime, peer_pub_key):
        """Returns the shared key, takes the public prime and the peer pub
        key as parameters."""
        return (peer_pub_key**self.priv_key)%public_prime

    def send(self, message):
        """Sends the given message to the output_traffic."""
        with open(self.output_traffic_file, "w", encoding="utf-8") as sender:
            sender.write(message)

    def listen(self, key_word):
        """This method listens on the input file, until a message
        comes in, then it returns the message."""
        listening = True
        while listening:
            with open(self.input_traffic_file, "r", encoding="utf-8") as listener:
                input_packet = listener.read()
                if input_packet.startswith(key_word):
                    return input_packet.split("::")

    def key_exchange_client(self):
        """This method initiates a key exchange."""
        self.send(self.gen_hello_message())
        print("LOG: CLIENT_HELLO message has been send.")
        incoming_packet = self.listen("SERVER_HELLO")
        print("LOG: SERVER_HELLO message has been received.")
        shared_key = self.shared_key_gen(
            int(incoming_packet[3]),
            int(incoming_packet[4])
        )
        print("LOG: Shared key has been calculated")
        self.shared_key = shared_key
        print(f"DEBUGING: shared key = {shared_key}")

    def key_exchange_server(self):
        """This method waits for a keychange to be initiated."""
        incoming_packet = self.listen("CLIENT_HELLO")
        print("LOG: CLIENT_HELLO message has been received.")
        self.send(self.gen_hello_message(
            incoming_packet[2],
            incoming_packet[3], incoming_packet[4]
            ))
        print("LOG: SERVER_HELLO message has been send.")
        shared_key = self.shared_key_gen(
            int(incoming_packet[3]),
            int(incoming_packet[4])
        )
        print("LOG: Shared key has been calculated")
        self.shared_key = shared_key
        print(f"DEBUGING: shared key = {shared_key}")

    def chiffre_send(self, message):
        """The method to send and receive messages,
        after an key exchange is established."""
        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        print(f"LOG: The message hash is: {message_hash}")
        print(f"DEBUGING: The message is: {message}")
        cipher = vigenere.encrypt(message, self.shared_key)
        print(f"LOG: The cipher is: {cipher}")
        to_be_send = self.gen_message(cipher, message_hash)
        self.send(to_be_send)
        print("LOG: MESSAGE has been send.")
        self.clear_receiving()

    def chiffre_receive(self):
        """This method listens for encrypted, incoming
        packages with type 'MESSAGE'. If such packet
        arrives, it verifies the hash, after that prints
        and returns the message."""
        incoming_packet = self.listen("MESSAGE")
        print("LOG: MESSAGE has been received.")
        message = vigenere.decrypt(incoming_packet[1], self.shared_key)
        print("LOG: Message has been succesfully decrypted.")
        if int(hashlib.sha256(message.encode()).hexdigest(), 16) == int(incoming_packet[2]):
            print("LOG: Message has been succesfully verified")
            print(f"LOG: The message is: {message}")
            return message
        print("WARNING: Message can not be verified.")
        print(f"WARNING: Sended hash is: {int(incoming_packet[2])}")
        print(f"WARNING: Calculated hash is: {int(hashlib.sha256(message.encode()).hexdigest(), 16)}")
        print(f"LOG: The message is: {message}")

    def main(self):
        """The main method, redistributes the work,
        that is to do."""
        if self.mode == "SERVER":
            self.key_exchange_server()
            if self.chiffre_receive() == "!CLOSE!":
                self.clear_transmitting()
                sys.exit(0)
            self.main_loop()

        else:
            self.key_exchange_client()
            self.main_loop()

    def main_loop(self):
        """Loop, to continously send and receive messages."""
        done = False
        while not done:
            input_message = input("Please enter a message, or a command; '?' for help: ")
            if input_message.lower == "?":
                print("type !close! to close the connection")
            elif input_message.upper in ("!CLOSE!", "!C!", "!QUIT!", "!Q!"):
                self.clear_transmitting()
                self.chiffre_send("!CLOSE!")
                print("Completed Tasks")
                sys.exit(0)
            else:
                self.chiffre_send(input_message)

            if self.chiffre_receive() == "!CLOSE!":
                self.clear_transmitting()
                sys.exit(0)
        sys.exit(0)

    def clear_transmitting(self):
        """Clears the output file."""
        self.send("")
        print("LOG: Output file has been cleared.")

    def clear_receiving(self):
        """Clears the input file."""
        with open(self.input_traffic_file, "w", encoding="utf-8") as sender:
            sender.write("")
        print("LOG: Inputfile has been cleared.")
