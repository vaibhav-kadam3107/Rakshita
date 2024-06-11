from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import os

def load_private_key():
    with open('private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key

def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        enc_session_key, nonce, tag, ciphertext = \
            [f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    print(f"Decrypting {file_path}:")
    print(f"  enc_session_key length: {len(enc_session_key)}")
    print(f"  nonce length: {len(nonce)}")
    print(f"  tag length: {len(tag)}")
    print(f"  ciphertext length: {len(ciphertext)}")

    cipher_rsa = PKCS1_OAEP.new(private_key)
    try:
        session_key = cipher_rsa.decrypt(enc_session_key)
    except ValueError as e:
        print(f"Error decrypting session key for {file_path}: {e}")
        return

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    try:
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(f"Error decrypting or verifying {file_path}: {e}")
        return

    with open(file_path, 'wb') as f:
        f.write(data)

def decrypt_directory(directory):
    private_key = load_private_key()

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and not file_path.endswith('.pem'):
            decrypt_file(file_path, private_key)
    
    print("Decryption complete.")

if __name__ == "__main__":
    directory = os.getcwd()
    print(f"Decrypting files in directory: {directory}")
    decrypt_directory(directory)

