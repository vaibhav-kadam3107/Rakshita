from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import os

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    with open('private.pem', 'wb') as f:
        f.write(private_key)
    with open('public.pem', 'wb') as f:
        f.write(public_key)

def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Generate a random AES key
    session_key = get_random_bytes(16)

    # Encrypt the data with AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Encrypt the AES key with RSA
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Overwrite the original file with the encrypted data
    with open(file_path, 'wb') as f:
        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

def encrypt_directory(directory):
    private_key, public_key = generate_keys()
    save_keys(private_key, public_key)

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            # Exclude script file and key files from encryption
            if filename not in ['encryption.py', 'decryption.py', 'public.pem', 'private.pem']:
                encrypt_file(file_path, public_key)
    
    print("Encryption complete. Your private key (save it securely):")
    print(private_key.decode())

if __name__ == "__main__":
    directory = os.getcwd()
    print(f"Encrypting files in directory: {directory}")
    encrypt_directory(directory)

