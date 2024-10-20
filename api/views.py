from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from Crypto.Cipher import AES, PKCS1_OAEP, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64
from Crypto.PublicKey import RSA

# In-memory storage for RSA keys
rsa_key_pair = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
public_key = rsa_key_pair.publickey().export_key()  # Export the public key for use

# Function to simulate Triple DES encryption
def des3_encrypt(data: str, key: bytes):
    data_bytes = data.encode('utf-8')
    cipher = DES3.new(key, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_bytes, DES3.block_size))
    return cipher.iv, ct_bytes

# Function to simulate AES encryption
def aes_encrypt(data: str, key: bytes):
    data_bytes = data.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
    return cipher.iv, ct_bytes

# Function to simulate RSA encryption
def rsa_encrypt(data: str, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    data_bytes = data.encode('utf-8')
    return cipher.encrypt(data_bytes)

@api_view(['POST'])
def model(request):
    text_input = request.data.get('text')
    attack = request.data.get('attack')

    if not text_input or not attack:
        return Response({'error': 'Text input and attack type are required.'}, status=400)

    if attack == "Grover Algorithm":
        # Triple DES Encryption (24-byte key)
        key = get_random_bytes(24)
        iv, ciphertext = des3_encrypt(text_input, key)
        return Response({
            'algo': 'Kyber a key encapsulation mechanism (KEM) designed to be resistant to cryptanalytic attacks with future powerful quantum computers.',
            'encrypted_text': ciphertext.hex(),
            'radarData': {'Security_Level': 9, 'Speed': 8, 'Key_Size':7,'Scalability': 8, 'Resource_Consumption': 7 }, # Return the key if needed
        })

    elif attack == "Shor Algorithm":
        # RSA Encryption
        rsa_ct = rsa_encrypt(text_input, rsa_key_pair.publickey())
        return Response({
            'algo': 'McEliece the McEliece system offers a unique approach to encryption by leveraging the difficulty of decoding in linear binary codes and quantum computers proof.',
            'encrypted_text': base64.b64encode(rsa_ct).decode('utf-8'),
            'radarData': {'Security_Level': 10, 'Speed': 6, 'Key_Size':5,'Scalability': 7, 'Resource_Consumption': 6 }, # Return the key if needed
        })

    elif attack == 'Brute Force':
        # AES Encryption (128-bit key)
        key = get_random_bytes(16)  # 128-bit key
        iv, ciphertext = aes_encrypt(text_input, key)
        return Response({
            'algo': 'AES(128-bit) a symmetric block cipher algorithm with a block/chunk size of 128 bits.',
            'encrypted_text': ciphertext.hex(),
            'radarData': {'Security_Level': 3, 'Speed': 9, 'Key_Size':5,'Scalability': 4, 'Resource_Consumption': 8 }, # Return the key if needed
# Return the key if needed
        })

    elif attack == 'Cryptoanalyzing':
        # AES Encryption (256-bit key)
        key = get_random_bytes(32)  # 256-bit key
        iv, ciphertext = aes_encrypt(text_input, key)
        return Response({
            'algo': 'AES(256-bit) a symmetric block cipher algorithm with a block/chunk size of 256 bits.',
            'encrypted_text': ciphertext.hex(),
            'radarData': {'Security_Level': 7, 'Speed': 8, 'Key_Size':9,'Scalability': 9, 'Resource_Consumption': 8 }, # Return the key if needed
 # Return the key if needed
        })

    return Response({'error': 'Invalid attack type'}, status=400)
