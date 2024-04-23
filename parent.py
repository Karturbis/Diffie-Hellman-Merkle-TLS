"""This file contains the Endpoint class,which can be instatiated as
a server or a client. The only differnce is, that the client starts
the connection, after Key-exchange, both have same funktionality.
For comunnication, a file writing system is used. Each instance
of the Endpoint class has an input- and an output-file. If the
Endpoint wants to send something, it writes it to the output-file."""

import sys
import random
import hashlib
import sympy
import symmetric_encryption


class Endpoint:
    """This class contains all methods needed by an endpoint"""

    def __init__(self, name, mode):
        self.priv_key = 42
        self.shared_key = 42
        self.name = name
        self.mode = mode
        self.main()

    def gen_prime(self, a = 2**16, b = 2**17):
        """Generates a random prime number between a and b,
        by generating a list of primes and then pick a
        random element of the list."""
        primes = [i for i in range(a, b) if sympy.isprime(i)]
        return random.choice(primes)

########################## Contents of this function need to be in calling function, so this function can be removed!
    def gen_hello_message(
        self, enc_protocol, public_generator = 42,
        public_prime = 42, peer_pub_key = 42
        ):
        """Generates the hello message for
        the key exchange.
        See pub_key_gen() for more information, about all
        parameters being 42 as the default."""
        public_generator, public_prime, self_pub_key = self.pub_key_gen(
            public_generator, public_prime, peer_pub_key
            )
        return str(
            "HELLO::" + self.name + "::" + enc_protocol
            + str(public_generator) + "::"
            + str(public_prime) + "::" + str(self_pub_key)
            )
##########################

    def gen_message(self, message_type, contents):
        """Generates a sendable message from
        a cipher and the message hash."""
        for i in range(len(contents)):
            contents[i] += "::"
        return (f"{message_type}::{self.name}::") + "".join([i for i in contents]).strip("::")

    def priv_key_gen(self, public_prime):
        """Creates the private key, which is a
        random integer smaller than public_prime."""
        return random.randint(1, int(public_prime) - 1)

    def pub_key_gen(
        self, public_generator = 42,
        public_prime = 42, peer_pub_key = 42
        ):
        """Generates the public key of the endpoint, if no
        parameters are given or all given parameters are 42, it
        also creates the public prime and the public generator.
        Public key is generated, using the standart
        Diffie-Hellman-Merkle method."""
        if public_generator == public_prime == peer_pub_key == 42:
            public_prime = self.gen_prime()
            public_generator = random.randint(2**12, int(public_prime)-1)
        self.priv_key = self.priv_key_gen(int(public_prime))
        self_pub_key = (
            int(public_generator)**self.priv_key)%int(public_prime
            )
        return public_generator, public_prime, self_pub_key

    def shared_key_gen(self, public_prime, peer_pub_key):
        """Returns the shared key, takes the public
        prime and the peer pub key as parameters."""
        return (peer_pub_key**self.priv_key)%public_prime

    def send(self, message, receiver):
        """Sends the given message to the output_traffic"""
        with open(f"to_{receiver}", "w", encoding="utf-8") as sender:
            sender.write(message)

    def keyword_listen(self, key_word):
        """Listens on the input file, until a
        message with the given keyword comes
        in, then it returns the message."""
        listening = True
        while listening:
            with open(
                self.input_traffic_file, "r", encoding="utf-8"
                ) as listener:
                input_packet = listener.read()
                if input_packet.startswith(key_word):
                    return input_packet.split("::")

    def key_exchange_client(self):
        """Initiates a key exchange."""
        self.send(self.gen_hello_message())
        print("LOG: CLIENT_HELLO message has been send.")
        incoming_packet = self.keyword_listen("SERVER_HELLO")
        print("LOG: SERVER_HELLO message has been received.")
        shared_key = self.shared_key_gen(
            int(incoming_packet[3]),
            int(incoming_packet[4])
        )
        print("LOG: Shared key has been calculated")
        self.shared_key = shared_key
        print(f"DEBUGING: shared key = {shared_key}")

    def key_exchange_server(self):
        """Waits for a keychange to be initiated 
        by the other endpoint."""
        incoming_packet = self.keyword_listen("CLIENT_HELLO")
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
        """Send and receive messages, after
        an key exchange is established."""
        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        print(f"LOG: The message hash is: {message_hash}")
        print(f"DEBUGING: The message is: {message}")
        cipher = symmetric_encryption.encrypt(message, self.shared_key)
        print(f"LOG: The cipher is: {cipher}")
        to_be_send = self.gen_message(cipher, message_hash)
        self.send(to_be_send)
        print("LOG: MESSAGE has been send.")
        self.clear_receiving()

    def chiffre_receive(self):
        """Listens for encrypted, incoming
        packages with type 'MESSAGE'. If such packet
        arrives, it verifies the hash, after that it
        prints and returns the message."""
        incoming_packet = self.keyword_listen("MESSAGE")
        print("LOG: MESSAGE has been received.")
        print(f"DEBUGING: The chiffre is: {incoming_packet[1]}")
        message = symmetric_encryption.decrypt(
            incoming_packet[1], self.shared_key
            )
        print("LOG: Message has been succesfully decrypted.")
        if int(hashlib.sha256(message.encode()).hexdigest(), 16) == int(
                incoming_packet[2]
                ):
            print("LOG: Message has been succesfully verified")
            print(f"LOG: The message is: {message}")
            return message
        print("WARNING: Message can not be verified.")
        print(f"WARNING: Received hash is: {int(incoming_packet[2])}")
        print(
            f"WARNING: Calculated hash is: "
            f"{int(hashlib.sha256(message.encode()).hexdigest(), 16)}")
        print(f"LOG: The unverified received message is: {message}")

    def main(self):
        """The main method, checks the mode,
        the program runs in and redistributes
        the work."""
        if self.mode == "SERVER":
            self.key_exchange_server()
            if self.chiffre_receive() == "!CLOSE!":
                self.clear_transmitting()
                sys.exit(0)
            self.main_loop()
        elif self.mode == "CLIENT":
            self.key_exchange_client()
            self.main_loop()
        else:
            print("WARNING: No available mode was selected.")

    def main_loop(self):
        """Loop, to continously send and receive messages."""
        done = False
        while not done:
            input_message = input(
                "Please enter a message, or a command; '?' for help: "
                )
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
