#!/usr/bin/env python2

'''
Created on 9-mei-2017

Information security project: Vehicle-to-vehicle communication

@authors: Jan Vermeulen, Maxime Fernandez Alonso, Isaura Claeys, Niels De Graef
'''
import os
import time
import glob
import certificates
from person import Person

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

# Create certificates if no '_CERT.pem'-files in the designated directory
print('Checking if certificate directory exists...')
if not os.path.isdir('certificates'):
    print('making directory')
    os.makedirs('certificates')

print('Checking if key and certificate files exist...')
if not glob.glob('certificates/*.pem'):
    print('creating keys and certificates')
    certificates.create_certificates()

# Initialize entities
print('initializing entities...')
alice = Person('ALICE')
bob = Person('BOB')

# Start init timer
DH_start_time = time.time()

# Set up session (Authenticated Ephemeral Diffie-Hellman Key Exchange
# + Certificate verification)
print('Starting EDH key exchange')
# DH: get peer's public key
alice.set_dh_peer_public_key(
    *bob.generate_dh_public_key(),
    peer_cert=bob.get_certificate()
)

bob.set_dh_peer_public_key(
    *alice.generate_dh_public_key(),
    peer_cert=alice.get_certificate()
)

# DH: shared secret (AES-128 key, hashed with SHA-256)
print('Creating shared key')
alice.calculate_symmetric_key()
bob.calculate_symmetric_key()

# Time needed for connection initialization
print('DH + authentication took %.2f ms.' % ((time.time() - DH_start_time)*1000.0))

# Start message timer
MSG_start_time = time.time()

# Send message from Alice to Bob
encrypted_msg, iv, tag, peer_cert = alice.encrypt(b'a very secret message!')
decrypted_str = bob.decrypt(encrypted_msg, iv, tag, peer_cert)
print('{} received "{}"'.format(bob.name, decrypted_str.decode('utf-8')))

# Bob sends ACK to Alice
signature, bob_ku = bob.sign_ack(decrypted_str)
alice.verify_ack_signature(decrypted_str, signature, bob_ku)
print('{} received an acknowledgement that Bob received her message correctly.'.format(alice.name))

# Time needed for connection initialization
print("Messaging + verification took %.2f ms." % ((time.time() - MSG_start_time)*1000.0))

# No termination required, just stop sending messages.
