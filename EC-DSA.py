from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.backends import default_backend

def generate_ecdsa_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdsa_sign(private_key, message):
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def ecdsa_verify(public_key, message, signature):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def test_ecdsa_oaep(): 
    private_key, public_key = generate_ecdsa_key_pair()
    message = b"Hello, EC-DSA!"
    signature = ecdsa_sign(private_key, message)
    valid = ecdsa_verify(public_key, message, signature)
    print("Valid signature:", valid)

test_ecdsa_oaep()
