'''
Created on 9-mei-2017

@authors: Jan Vermeulen, Maxime Fernandez Alonso, Isaura Claeys, Niels De Graef
'''
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import ec


class Person():
    def __init__(self, name):
        self.name = name
        self.seq = 0

        # Load certificate
        pem_data = open('certificates/' + self.name + '_CERT.pem').read()
        self.cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        self.ku = self.cert.public_key()

        # Load private key
        pem_data = open('certificates/' + self.name + '_KR.pem').read()
        self.kr = serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend()
        )

        # Get certificate of ca
        pem_data = open('certificates/CA_KU.pem').read()
        self.ca_ku = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )

        print(name + ' initialized')

    def generate_dh_public_key(self):
        # Generate DH key pair
        print('Generating DH public/private key pair')
        self.dh_private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        self.dh_public_key = self.dh_private_key.public_key()

        # Sign DH public key
        print('signing public key DH with private key')
        signature = self.kr.sign(
            self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            ec.ECDSA(hashes.SHA256())
        )

        return (self.dh_public_key, signature)

    def set_dh_peer_public_key(self, dh_peer_public_key, signature, peer_cert):
        print('received DH public key from peer')
        self.dh_peer_public_key = dh_peer_public_key

        # Authenticate peer by verifying his certificate
        print('verifying certificate of peer')
        self.ca_ku.verify(
             peer_cert.signature,
             peer_cert.tbs_certificate_bytes,
             ec.ECDSA(hashes.SHA256())
        )

        # Verify signature using RSA public key of peer
        print('verifiying signature of public key')
        peer_cert.public_key().verify(
             signature,
             dh_peer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
             ),
             ec.ECDSA(hashes.SHA256())
         )

    def calculate_symmetric_key(self):
        # Calculating DH secret key
        secret_symm_key = self.dh_private_key.exchange(ec.ECDH(), self.dh_peer_public_key)
        # Hashing shared key to 256 for AES-128
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret_symm_key)
        self.aes_key = digest.finalize()[:16]
        print(self.name + ': Symmetric key generated')

    def get_certificate(self):
        return self.cert

    def encrypt(self, msg):
        print('encrypting message...')
        iv = os.urandom(16) # random for every encryption, prefix it to the cyphertext NOT SECRET
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ct = encryptor.update(msg) + encryptor.finalize()

        print('done')
        return ct, iv, encryptor.tag, self.cert

    def decrypt(self, ct, iv, tag, peer_cert):
        print('decrypting message...')
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(ct) + decryptor.finalize()

        # Authenticate peer by verifying his certificate
        self.ca_ku.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        return decrypted
    
    def sign_ack(self, message):
        return self.kr.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        ), self.ku
        
    def verify_ack_signature(self, message, signature, peer_ku):
        peer_ku.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
