#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import MD5
import base64


class ModernEncryption:
    @staticmethod
    def _get_mode(mode: str):
        modes = {
            'ECB': AES.MODE_ECB,
            'CBC': AES.MODE_CBC,
            'CFB': AES.MODE_CFB,
            'OFB': AES.MODE_OFB,
            'CTR': AES.MODE_CTR
        }
        return modes.get(mode.upper(), AES.MODE_ECB)
    
    @staticmethod
    def _prepare_key(key: str, key_size: int = 16) -> bytes:
        key = key.encode('utf-8')
        return (key + b'\x00' * key_size)[:key_size]
    
    @staticmethod
    def _format_output(ciphertext: bytes, output_format: str) -> str:
        return base64.b64encode(ciphertext).decode('utf-8') if output_format.lower() == 'base64' else ciphertext.hex()
    
    @staticmethod
    def _parse_input(ciphertext: str, input_format: str) -> bytes:
        return base64.b64decode(ciphertext) if input_format.lower() == 'base64' else bytes.fromhex(ciphertext)
    
    @staticmethod
    def _block_cipher_encrypt(plaintext: str, key: str, cipher_class, key_size: int, mode: str = 'ECB', output_format: str = 'base64') -> str:
        key_bytes = ModernEncryption._prepare_key(key, key_size)
        mode_upper = mode.upper()
        
        if mode_upper == 'ECB':
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode))
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), cipher_class.block_size))
        elif mode_upper == 'CBC':
            iv = get_random_bytes(cipher_class.block_size)
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv)
            ciphertext = iv + cipher.encrypt(pad(plaintext.encode('utf-8'), cipher_class.block_size))
        elif mode_upper in ('CFB', 'OFB'):
            iv = get_random_bytes(cipher_class.block_size)
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv)
            ciphertext = iv + cipher.encrypt(plaintext.encode('utf-8'))
        elif mode_upper == 'CTR':
            nonce = get_random_bytes(cipher_class.block_size // 2)
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), nonce=nonce)
            ciphertext = nonce + cipher.encrypt(plaintext.encode('utf-8'))
        
        return ModernEncryption._format_output(ciphertext, output_format)
    
    @staticmethod
    def _block_cipher_decrypt(ciphertext: str, key: str, cipher_class, key_size: int, mode: str = 'ECB', input_format: str = 'base64') -> str:
        key_bytes = ModernEncryption._prepare_key(key, key_size)
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        mode_upper = mode.upper()
        
        if mode_upper == 'ECB':
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode))
            plaintext = unpad(cipher.decrypt(ciphertext_bytes), cipher_class.block_size)
        elif mode_upper == 'CBC':
            iv = ciphertext_bytes[:cipher_class.block_size]
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv)
            plaintext = unpad(cipher.decrypt(ciphertext_bytes[cipher_class.block_size:]), cipher_class.block_size)
        elif mode_upper in ('CFB', 'OFB'):
            iv = ciphertext_bytes[:cipher_class.block_size]
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv)
            plaintext = cipher.decrypt(ciphertext_bytes[cipher_class.block_size:])
        elif mode_upper == 'CTR':
            nonce = ciphertext_bytes[:cipher_class.block_size // 2]
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), nonce=nonce)
            plaintext = cipher.decrypt(ciphertext_bytes[cipher_class.block_size // 2:])
        
        return plaintext.decode('utf-8', errors='ignore')
    
    @staticmethod
    def aes_encrypt(plaintext: str, key: str, mode: str = 'ECB', output_format: str = 'base64') -> str:
        return ModernEncryption._block_cipher_encrypt(plaintext, key, AES, 16, mode, output_format)
    
    @staticmethod
    def aes_decrypt(ciphertext: str, key: str, mode: str = 'ECB', input_format: str = 'base64') -> str:
        return ModernEncryption._block_cipher_decrypt(ciphertext, key, AES, 16, mode, input_format)
    
    @staticmethod
    def des_encrypt(plaintext: str, key: str, mode: str = 'ECB', output_format: str = 'base64') -> str:
        return ModernEncryption._block_cipher_encrypt(plaintext, key, DES, 8, mode, output_format)
    
    @staticmethod
    def des_decrypt(ciphertext: str, key: str, mode: str = 'ECB', input_format: str = 'base64') -> str:
        return ModernEncryption._block_cipher_decrypt(ciphertext, key, DES, 8, mode, input_format)
    
    @staticmethod
    def tdes_encrypt(plaintext: str, key: str, mode: str = 'ECB', output_format: str = 'base64') -> str:
        return ModernEncryption._block_cipher_encrypt(plaintext, key, DES3, 24, mode, output_format)
    
    @staticmethod
    def tdes_decrypt(ciphertext: str, key: str, mode: str = 'ECB', input_format: str = 'base64') -> str:
        return ModernEncryption._block_cipher_decrypt(ciphertext, key, DES3, 24, mode, input_format)
    
    @staticmethod
    def _rc4_operation(data: bytes, key: bytes) -> bytes:
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        result = []
        i = j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result)
    
    @staticmethod
    def rc4_encrypt(plaintext: str, key: str, output_format: str = 'base64') -> str:
        key_bytes = ModernEncryption._prepare_key(key, 16)
        ciphertext_bytes = ModernEncryption._rc4_operation(plaintext.encode('utf-8'), key_bytes)
        return ModernEncryption._format_output(ciphertext_bytes, output_format)
    
    @staticmethod
    def rc4_decrypt(ciphertext: str, key: str, input_format: str = 'base64') -> str:
        key_bytes = ModernEncryption._prepare_key(key, 16)
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        plaintext_bytes = ModernEncryption._rc4_operation(ciphertext_bytes, key_bytes)
        return plaintext_bytes.decode('utf-8', errors='ignore')
    
    @staticmethod
    def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 16, iv_len: int = 0) -> bytes:
        """OpenSSL EVP_BytesToKey密钥派生函数"""
        from Crypto.Hash import MD5
        
        key_iv = b''
        last_hash = b''
        
        while len(key_iv) < key_len + iv_len:
            md5 = MD5.new()
            md5.update(last_hash)
            md5.update(password)
            md5.update(salt)
            last_hash = md5.digest()
            key_iv += last_hash
        
        return key_iv[:key_len + iv_len]
    
    @staticmethod
    def rc4_encrypt_openssl(plaintext: str, key: str, output_format: str = 'base64') -> str:
        salt = get_random_bytes(8)
        derived_key = ModernEncryption._evp_bytes_to_key(key.encode('utf-8'), salt, key_len=32)
        ciphertext_bytes = ModernEncryption._rc4_operation(plaintext.encode('utf-8'), derived_key)
        return ModernEncryption._format_output(b'Salted__' + salt + ciphertext_bytes, output_format)
    
    @staticmethod
    def rc4_decrypt_openssl(ciphertext: str, key: str, input_format: str = 'base64') -> str:
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        
        if not ciphertext_bytes.startswith(b'Salted__'):
            raise ValueError("Invalid OpenSSL format: missing 'Salted__' prefix")
        
        salt = ciphertext_bytes[8:16]
        encrypted_data = ciphertext_bytes[16:]
        derived_key = ModernEncryption._evp_bytes_to_key(key.encode('utf-8'), salt, key_len=32)
        plaintext_bytes = ModernEncryption._rc4_operation(encrypted_data, derived_key)
        return plaintext_bytes.decode('utf-8', errors='ignore')
