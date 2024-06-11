from PIL import Image
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import sys

def encrypt(data, password):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from the password
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())

    # Generate a random IV
    iv = os.urandom(16)

    # Pad data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt, iv, and encrypted data
    encrypted_message = salt + iv + encrypted_data
    return encrypted_message

def decrypt(encrypted_message, password):
    # Extract salt, iv, and encrypted data
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    encrypted_data = encrypted_message[32:]

    # Derive the key from the password
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return data

def embed_file(image_path, file_path, output_image_path, password):
    # Read the private key file
    with open(file_path, 'rb') as file:
        data = file.read()

    # Encrypt the data
    encrypted_data = encrypt(data, password)

    # Add length header to the encrypted data
    length_header = len(encrypted_data).to_bytes(4, 'big')
    encrypted_data_with_header = length_header + encrypted_data

    # Convert data to binary
    binary_data = ''.join([format(byte, '08b') for byte in encrypted_data_with_header])
    data_len = len(binary_data)

    # Load the image
    image = Image.open(image_path)
    encoded = image.copy()
    width, height = image.size

    # Check if the image is large enough to hold the data
    if data_len > width * height * 3:
        raise ValueError("Data is too large to fit in the image")

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index < data_len:
                pixel = list(image.getpixel((x, y)))
                for n in range(3):  # Modify R, G, B values
                    if data_index < data_len:
                        pixel[n] = pixel[n] & ~1 | int(binary_data[data_index])
                        data_index += 1
                encoded.putpixel((x, y), tuple(pixel))

    encoded.save(output_image_path)
    print(f"File embedded in image and saved as {output_image_path}")

def extract_file(image_path, output_file_path, password):
    # Load the image
    image = Image.open(image_path)
    binary_data = ""

    for y in range(image.height):
        for x in range(image.width):
            pixel = image.getpixel((x, y))
            for n in range(3):  # Extract from R, G, B values
                binary_data += str(pixel[n] & 1)

    # Convert binary data to bytes
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    extracted_data = bytearray([int(byte, 2) for byte in all_bytes])

    # Extract length header
    length_header = extracted_data[:4]
    data_length = int.from_bytes(length_header, 'big')

    # Extract encrypted data
    encrypted_data = extracted_data[4:4 + data_length]

    # Decrypt the data
    data = decrypt(bytes(encrypted_data), password)

    # Save the extracted data to a file
    with open(output_file_path, 'wb') as file:
        file.write(data)

    print(f"Data extracted from image and saved as {output_file_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python steganography.py [embed/extract] [args...]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "embed":
        if len(sys.argv) != 6:
            print("Usage: python steganography.py embed <image_path> <file_path> <output_image_path> <password>")
            sys.exit(1)
        embed_file(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif command == "extract":
        if len(sys.argv) != 5:
            print("Usage: python steganography.py extract <image_path> <output_file_path> <password>")
            sys.exit(1)
        extract_file(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print("Unknown command:", command)
        sys.exit(1)

