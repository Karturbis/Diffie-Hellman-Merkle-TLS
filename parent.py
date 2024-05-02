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
    """Contains all methods needed by an endpoint"""

    def __init__(self, name):
        self.priv_key = 42
        self.shared_key = 42
        self.encryption_protocol = "CAESAR"
        self.name = name
        self.peer_variables = {} # keys are in the scheme: {priv_key, pub_gen, pub_prime, self_pub, other_pub, shared_key}
        self.main()

    def gen_prime(self, a = 2**16, b = 2**17):
        """Generates a random prime number between a and b,
        by generating a list of primes and then pick a
        random element of the list."""
        primes = [i for i in range(a, b) if sympy.isprime(i)]
        return random.choice(primes)

    def gen_message(self, message_type, contents):
        """Generates a sendable message."""
        print(f"DEBUG: Contents at begin of gen_message: {contents}")
        for i, _ in enumerate(contents):
            contents[i] = str(contents[i])
            contents[i] += "::"
            print(f"DEBUG: hello from for loop i = {contents[i]}")
        print(f"Contents is now: {contents}")
        x = (f"{message_type}::{self.name}::") + "".join(contents).strip(":")
        print(f"DEBUG: message to send: {x}")
        return x

    def priv_key_gen(self, public_prime):
        """Creates the private key, which is a
        random integer smaller than public_prime."""
        return random.randint(1, int(public_prime) - 1)

    def key_gen(
        self, public_generator = 42,
        public_prime = 42, peer_pub_key = 42
        ):
        """Generates the public key of the endpoint, if no
        parameters are given or all given parameters are 42, it
        also creates the public prime and the public generator.
        Public key is generated, using the standard
        Diffie-Hellman-Merkle method."""
        if public_generator == public_prime == peer_pub_key == 42:
            public_prime = self.gen_prime()
            public_generator = random.randint(2**12, int(public_prime)-1)
        priv_key = self.priv_key_gen(int(public_prime))
        self_pub_key = pow(public_generator, priv_key, public_prime)
        print(f"priv_key is: {priv_key}")
        return [priv_key, public_generator, public_prime, self_pub_key, peer_pub_key]

    def shared_key_gen(self, public_prime, peer_pub_key, priv_key):
        """Returns the shared key, takes the public
        prime and the peer pub key as parameters."""
        return pow(peer_pub_key, priv_key, public_prime) # returns peer_pub_key ^ priv_key modulo public_prime

    def send(self, message, receiver, channel):
        """Sends the given message to the output_traffic"""
        with open(f"to_{receiver.lower()}_channel-{channel}", "w", encoding="utf-8") as sender:
            sender.write(message)

    def keyword_listen(self, key_word, channel):
        """Listens on the input file, until a
        message with the given keyword comes
        in, then it returns the message."""

        listening = True
        while listening:
            with open(
                f"to_{self.name.lower()}_channel-{channel}", "r", encoding="utf-8"
                ) as listener:
                input_packet = listener.read()
                if input_packet.startswith(key_word):
                    listening = False
        return input_packet.split("::")

    def key_exchange_init(self, peer, encryption_protocol, channel = 12):
        """Initiates a key exchange."""
        self.peer_variables[peer] = {"keys":self.key_gen()}
        print(f"DEBUG: peer_variables = {self.peer_variables}")
        message = self.peer_variables[peer]["keys"][1:4]
        message.insert(0, channel)
        message.insert(0, encryption_protocol)
        self.send(self.gen_message("HELLO", message), peer, 0)
        print("LOG: HELLO message has been send.")
        incoming_packet = self.keyword_listen("HELLO", 0)
        print("LOG: HELLO message has been received.")
        self.peer_variables[peer]["keys"].insert(-1, int(incoming_packet[6]))
        shared_key = self.shared_key_gen(
            int(incoming_packet[5]),
            int(incoming_packet[6]),
            int(self.peer_variables[peer]["keys"][0])
        )
        print("LOG: Shared key has been calculated")
        del self.peer_variables[peer]["keys"][5]
        self.peer_variables[peer]["keys"].append(shared_key)
        print(f"DEBUG: claculated peer variables are: {self.peer_variables}")
        print(f"DEBUGING: shared key = {shared_key}")

    def key_exchange_wait(self, channel = 42):
        """Waits for a keychange to be initiated 
        by the other endpoint."""
        print("start waiting for key ex")
        incoming_packet = self.keyword_listen("HELLO", 0)
        print("LOG: HELLO message has been received.")
        peer = incoming_packet[1]
        self.peer_variables[peer]= {"keys":self.key_gen(
            int(incoming_packet[4]),
            int(incoming_packet[5]),
            int(incoming_packet[6])
            )
        }
        print(f"DEBUG: claculated peer variables are: {self.peer_variables}")
        peer_vars_to_be_send = self.peer_variables[peer]["keys"][1:4]
        peer_vars_to_be_send.insert(0, channel)
        peer_vars_to_be_send.insert(0, self.encryption_protocol)
        to_be_send = self.gen_message("HELLO", peer_vars_to_be_send)
        self.send(to_be_send, peer, 0)
        print("LOG: HELLO message has been send.")
        shared_key = self.shared_key_gen(
            int(incoming_packet[5]),
            int(incoming_packet[6]),
            self.peer_variables[peer]["keys"][0]
        )
        print("LOG: Shared key has been calculated")
        self.peer_variables[peer]["keys"].append(shared_key)
        print(f"DEBUGING: Keys are = {self.peer_variables}")
        print(f"DEBUGING: G = {incoming_packet[4]}")
        print(f"DEBUGING: P = {incoming_packet[5]}")
        print(f"DEBUGING: A = {incoming_packet[6]}")
        print(f"DEBUGING: Schared Key = {shared_key}")

    def chiffre_send(self, message, receiver, channel):
        """Send and receive messages, after
        an key exchange is established."""
        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        print(f"LOG: The message hash is: {message_hash}")
        print(f"DEBUGING: The message is: {message}")
        cipher = symmetric_encryption.encrypt(message, self.shared_key)
        print(f"LOG: The cipher is: {cipher}")
        to_be_send = self.gen_message("MESSAGE", [cipher, message_hash])
        self.send(to_be_send, receiver, channel)
        print("LOG: MESSAGE has been send.")

    def chiffre_receive(self, channel):
        """Listens for encrypted, incoming
        packages with type 'MESSAGE'. If such packet
        arrives, it verifies the hash, after that it
        prints and returns the message."""
        incoming_packet = self.keyword_listen("MESSAGE", channel)
        print("LOG: MESSAGE has been received.")
        print(f"DEBUGING: The chiffre is: {incoming_packet[2]}")
        message = symmetric_encryption.decrypt(
            incoming_packet[2], self.shared_key
            )
        print("LOG: Message has been succesfully decrypted.")
        if int(hashlib.sha256(message.encode()).hexdigest(), 16) == int(
                incoming_packet[3]
                ):
            print("LOG: Message has been succesfully verified")
            print(f"LOG: The message is: {message}")
            self.clear_receiving(channel)
            return message
        print("WARNING: Message can not be verified.")
        print(f"WARNING: Received hash is: {int(incoming_packet[3])}")
        print(
            f"WARNING: Calculated hash is: "
            f"{int(hashlib.sha256(message.encode()).hexdigest(), 16)}")
        print(f"LOG: The unverified received message is: {message}")
        self.clear_receiving(channel)
        return message

    def main(self):
        """The main method, checks the mode,
        the program runs in and redistributes
        the work."""
        self.main_loop()

    def main_loop(self):
        """Loop, to continously send and receive messages."""
        done = False
        while not done:
            input_message = input(
                "Please enter a message, or a command; '?' for help: "
                ).split("::")
            if input_message[0] == "IKE":
                receiver = input_message[1]
                self.key_exchange_init(receiver, self.encryption_protocol)
                continue
            elif input_message[0] == "WKE":
                self.key_exchange_wait()
                continue
            receiver = input_message[0].lower()
            self.chiffre_send(input_message[1], receiver, 12)
        sys.exit(0)

    def clear_receiving(self, channel):
        """Clears the input file."""
        with open(f"to_{self.name}_channel-{channel}", "w", encoding="utf-8") as sender:
            sender.write("")
        print("LOG: Inputfile has been cleared.")
