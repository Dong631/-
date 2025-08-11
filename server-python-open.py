from flask import Flask, request, jsonify, session
from flask_cors import CORS
import os
import time
import hashlib
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')  # 从环境变量读取密钥
CORS(app, supports_credentials=True)  # 允许跨域请求并支持凭证

# 内存数据库 - 在实际生产环境中应替换为真实数据库
users = {}
chats = []
online_users = set()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'default-admin-password')  # 从环境变量读取管理员密码

# 数据持久化 - 将数据保存到文件
DATA_FILE = 'app_data.json'

def save_data():
    pass  # 空函数占位符
    
# 第一重加密：基于字符编码的加密
def encode_with_number(text, key):
    if not text: return ''
    result = ''
    for i in range(len(text)):
        char_code = ord(text[i])
        encrypted_code = (char_code + key) % 65536
        result += chr(encrypted_code)
    return result

# 第一重解密：基于字符编码的解密
def decode_with_number(text, key):
    if not text: return ''
    result = ''
    for i in range(len(text)):
        char_code = ord(text[i])
        decrypted_code = (char_code - key) % 65536
        if decrypted_code < 0:
            decrypted_code += 65536
        result += chr(decrypted_code)
    return result

# 第二重加密：维吉尼亚加密
def vigenere_encrypt(text, key):
    if not text or not key: return ''
    result = ''
    key = key.upper()
    key_index = 0
    for i in range(len(text)):
        char = text[i]
        # 处理大写字母
        if 'A' <= char <= 'Z':
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            encrypted_char_code = ((ord(char) - ord('A') + shift) % 26) + ord('A')
            result += chr(encrypted_char_code)
            key_index += 1
        # 处理小写字母
        elif 'a' <= char <= 'z':
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            encrypted_char_code = ((ord(char) - ord('a') + shift) % 26) + ord('a')
            result += chr(encrypted_char_code)
            key_index += 1
        # 非字母字符不加密
        else:
            result += char
    return result

# 第二重解密：维吉尼亚解密
def vigenere_decrypt(text, key):
    if not text or not key: return ''
    result = ''
    key = key.upper()
    key_index = 0
    for i in range(len(text)):
        char = text[i]
        # 处理大写字母
        if 'A' <= char <= 'Z':
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            decrypted_char_code = (ord(char) - ord('A') - shift) % 26
            if decrypted_char_code < 0: decrypted_char_code += 26
            decrypted_char_code += ord('A')
            result += chr(decrypted_char_code)
            key_index += 1
        # 处理小写字母
        elif 'a' <= char <= 'z':
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            decrypted_char_code = (ord(char) - ord('a') - shift) % 26
            if decrypted_char_code < 0: decrypted_char_code += 26
            decrypted_char_code += ord('a')
            result += chr(decrypted_char_code)
            key_index += 1
        # 非字母字符不解密
        else:
            result += char
    return result

# 双重加密函数
def double_encrypt(text, private_key, key_type):
    if not text: return ''
    # 第一层：基于字符编码的加密
    encrypted_once = encode_with_number(text, private_key if key_type == 'number' else len(private_key))
    # 第二层：维吉尼亚加密
    key_for_vigenere = private_key if key_type == 'letter' else chr(65 + (private_key % 26))
    encrypted_final = vigenere_encrypt(encrypted_once, key_for_vigenere)
    return encrypted_final

# 双重解密函数
def double_decrypt(text, private_key, key_type):
    if not text: return ''
    # 第一层解密：维吉尼亚解密
    key_for_vigenere = private_key if key_type == 'letter' else chr(65 + (private_key % 26))
    decrypted_once = vigenere_decrypt(text, key_for_vigenere)
    # 第二层解密：基于字符编码的解密
    decrypted_final = decode_with_number(decrypted_once, private_key if key_type == 'number' else len(private_key))
    return decrypted_final

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    text = data.get('text')
    key = data.get('key')
    key_type = data.get('key_type', 'number')
    if not text or not key:
        return jsonify({'error': '缺少必要参数'}), 400
    try:
        if key_type == 'number':
            key = int(key)
            if key < 1 or key > 255:
                return jsonify({'error': '数字密钥必须在1-255之间'}), 400
        elif key_type == 'letter':
            if not key.isalpha():
                return jsonify({'error': '英文密钥只能包含字母'}), 400
        result = double_encrypt(text, key, key_type)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    text = data.get('text')
    key = data.get('key')
    key_type = data.get('key_type', 'number')
    if not text or not key:
        return jsonify({'error': '缺少必要参数'}), 400
    try:
        if key_type == 'number':
            key = int(key)
            if key < 1 or key > 255:
                return jsonify({'error': '数字密钥必须在1-255之间'}), 400
        elif key_type == 'letter':
            if not key.isalpha():
                return jsonify({'error': '英文密钥只能包含字母'}), 400
        result = double_decrypt(text, key, key_type)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 添加根路由
@app.route('/')
def home():
    # 读取 HTML 文件内容
    html_path = os.path.join(os.path.dirname(__file__), 'simplified-encryption.html')
    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    return html_content, 200, {'Content-Type': 'text/html'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)