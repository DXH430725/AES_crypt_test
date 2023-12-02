import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import time

def encrypt_message(key, message):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Add a timestamp to the message
    timestamp = str(time.time()).encode('utf-8')
    print(timestamp)
    message_with_timestamp = timestamp + b' ' + message.encode('utf-8')
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_with_timestamp) + encryptor.finalize()
    
    # Include IV in the encrypted message
    encrypted_message = iv + ciphertext
    
    return encrypted_message

# 设置目标IP和端口
target_ip = '124.220.12.12'
target_port = 8080

# 设置AES密钥
aes_key = b'0123456789abcdef'

# 创建Socket对象
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到目标
client_socket.connect((target_ip, target_port))

# 输入待发送的消息
message_to_send = input("输入要发送的消息：")

# 加密消息
encrypted_message = encrypt_message(aes_key, message_to_send)

# 发送加密后的消息
client_socket.send(encrypted_message)

# 关闭连接
client_socket.close()
