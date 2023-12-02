#!/usr/bin/env python3

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import time

def decrypt_message(key, encrypted_message):
    # Extract the IV from the first 16 bytes
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Split the decrypted message into timestamp and actual message
    decrypted_message_parts = decrypted_bytes.split(b' ', 1)
    timestamp = float(decrypted_message_parts[0].decode('utf-8', 'ignore'))
    actual_message = decrypted_message_parts[1].decode('utf-8', 'ignore')
    
    # Calculate the delay
    current_time = time.time()
    delay = current_time - timestamp 
    
    print(f"传递消息: {encrypted_message}")
    
    return actual_message

# 设置本地IP和端口
local_ip = '10.0.16.16'
local_port = 2023

# 设置AES密钥（要与发送端相同）
aes_key = b'0123456789abcdef'

# 创建Socket对象
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 绑定到本地IP和端口
server_socket.bind((local_ip, local_port))

# 开始监听
server_socket.listen(1)

print(f"等待连接...")

# 接受连接
client_socket, addr = server_socket.accept()
print(f"连接来自 {addr}")

# 接收加密后的消息
encrypted_message = client_socket.recv(1024)

# 解密消息
decrypted_message = decrypt_message(aes_key, encrypted_message)

print(f"解密后的消息: {decrypted_message}")

# 关闭连接
client_socket.close()
server_socket.close()
