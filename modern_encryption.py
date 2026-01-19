#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import struct


class ModernEncryption:
    @staticmethod
    def _get_mode(mode: str):
        modes = {
            'ECB': AES.MODE_ECB,
            'CBC': AES.MODE_CBC,
            'CFB': AES.MODE_CFB,
            'OFB': AES.MODE_OFB,
            'CTR': AES.MODE_CTR,
            'GCM': AES.MODE_GCM
        }
        mode_upper = mode.upper()
        if mode_upper not in modes:
            raise ValueError(f"不支持的加密模式: {mode}。支持的模式: {', '.join(modes.keys())}")
        return modes[mode_upper]
    
    @staticmethod
    def _prepare_key(key: str, key_size: int = 16, salt: bytes = None) -> bytes:
        if salt is None:
            salt = get_random_bytes(16)
        derived_key = PBKDF2(key, salt, dkLen=key_size, count=100000, hmac_hash_module=SHA256)
        return derived_key, salt
    
    @staticmethod
    def _format_output(ciphertext: bytes, output_format: str) -> str:
        return base64.b64encode(ciphertext).decode('utf-8') if output_format.lower() == 'base64' else ciphertext.hex()
    
    @staticmethod
    def _parse_input(ciphertext: str, input_format: str) -> bytes:
        return base64.b64decode(ciphertext) if input_format.lower() == 'base64' else bytes.fromhex(ciphertext)
    
    @staticmethod
    def _block_cipher_encrypt(plaintext: str, key: str, cipher_class, key_size: int, mode: str = 'CBC', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        key_bytes = key.encode('utf-8')
        key_bytes = key_bytes[:key_size].ljust(key_size, b'\x00')
        mode_upper = mode.upper()
        
        padding_map = {
            'pkcs7': pad,
            'iso7816': lambda data, size: pad(data, size, padstyle='iso7816_4'),
            'x923': lambda data, size: pad(data, size, padstyle='x923'),
            'iso10126': lambda data, size: pad(data, size, padstyle='iso10126_2'),
            'zero': lambda data, size: data + b'\x00' * (size - (len(data) % size))
        }
        
        pad_func = padding_map.get(padding.lower(), pad)
        
        if mode_upper == 'ECB':
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode))
            ciphertext = cipher.encrypt(pad_func(plaintext.encode('utf-8'), cipher_class.block_size))
            return ModernEncryption._format_output(ciphertext, output_format)
        elif mode_upper == 'CBC':
            if iv is None:
                iv = get_random_bytes(cipher_class.block_size)
            else:
                iv = iv.encode('utf-8') if isinstance(iv, str) else iv
                iv = iv[:cipher_class.block_size].ljust(cipher_class.block_size, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv)
            ciphertext = cipher.encrypt(pad_func(plaintext.encode('utf-8'), cipher_class.block_size))
            return ModernEncryption._format_output(iv + ciphertext, output_format)
        elif mode_upper in ('CFB', 'OFB'):
            if iv is None:
                iv = get_random_bytes(cipher_class.block_size)
            else:
                iv = iv.encode('utf-8') if isinstance(iv, str) else iv
                iv = iv[:cipher_class.block_size].ljust(cipher_class.block_size, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            return ModernEncryption._format_output(iv + ciphertext, output_format)
        elif mode_upper == 'CTR':
            if iv is None:
                nonce = get_random_bytes(cipher_class.block_size // 2)
            else:
                nonce = iv.encode('utf-8') if isinstance(iv, str) else iv
                nonce = nonce[:cipher_class.block_size // 2].ljust(cipher_class.block_size // 2, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), nonce=nonce)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            return ModernEncryption._format_output(nonce + ciphertext, output_format)
        elif mode_upper == 'GCM':
            if iv is None:
                nonce = get_random_bytes(16)
            else:
                nonce = iv.encode('utf-8') if isinstance(iv, str) else iv
                nonce = nonce[:16].ljust(16, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
            return ModernEncryption._format_output(nonce + tag + ciphertext, output_format)
    
    @staticmethod
    def _block_cipher_decrypt(ciphertext: str, key: str, cipher_class, key_size: int, mode: str = 'CBC', input_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        mode_upper = mode.upper()
        
        key_bytes = key.encode('utf-8')
        key_bytes = key_bytes[:key_size].ljust(key_size, b'\x00')
        
        padding_map = {
            'pkcs7': unpad,
            'iso7816': lambda data, size: unpad(data, size, padstyle='iso7816_4'),
            'x923': lambda data, size: unpad(data, size, padstyle='x923'),
            'iso10126': lambda data, size: unpad(data, size, padstyle='iso10126_2'),
            'zero': lambda data, size: data.rstrip(b'\x00')
        }
        
        unpad_func = padding_map.get(padding.lower(), unpad)
        
        if mode_upper == 'ECB':
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode))
            plaintext = unpad_func(cipher.decrypt(ciphertext_bytes), cipher_class.block_size)
        elif mode_upper == 'CBC':
            iv_bytes = ciphertext_bytes[:cipher_class.block_size]
            if iv is not None:
                iv_bytes = iv.encode('utf-8') if isinstance(iv, str) else iv
                iv_bytes = iv_bytes[:cipher_class.block_size].ljust(cipher_class.block_size, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv_bytes)
            plaintext = unpad_func(cipher.decrypt(ciphertext_bytes[cipher_class.block_size:]), cipher_class.block_size)
        elif mode_upper in ('CFB', 'OFB'):
            iv_bytes = ciphertext_bytes[:cipher_class.block_size]
            if iv is not None:
                iv_bytes = iv.encode('utf-8') if isinstance(iv, str) else iv
                iv_bytes = iv_bytes[:cipher_class.block_size].ljust(cipher_class.block_size, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), iv_bytes)
            plaintext = cipher.decrypt(ciphertext_bytes[cipher_class.block_size:])
        elif mode_upper == 'CTR':
            nonce_bytes = ciphertext_bytes[:cipher_class.block_size // 2]
            if iv is not None:
                nonce_bytes = iv.encode('utf-8') if isinstance(iv, str) else iv
                nonce_bytes = nonce_bytes[:cipher_class.block_size // 2].ljust(cipher_class.block_size // 2, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), nonce=nonce_bytes)
            plaintext = cipher.decrypt(ciphertext_bytes[cipher_class.block_size // 2:])
        elif mode_upper == 'GCM':
            nonce_bytes = ciphertext_bytes[:16]
            tag_bytes = ciphertext_bytes[16:32]
            if iv is not None:
                nonce_bytes = iv.encode('utf-8') if isinstance(iv, str) else iv
                nonce_bytes = nonce_bytes[:16].ljust(16, b'\x00')
            cipher = cipher_class.new(key_bytes, ModernEncryption._get_mode(mode), nonce=nonce_bytes)
            plaintext = cipher.decrypt_and_verify(ciphertext_bytes[32:], tag_bytes)
        
        return plaintext.decode('utf-8', errors='ignore')
    
    @staticmethod
    def aes_encrypt(plaintext: str, key: str, mode: str = 'CBC', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption._block_cipher_encrypt(plaintext, key, AES, 16, mode, output_format, iv, padding)
    
    @staticmethod
    def aes_decrypt(ciphertext: str, key: str, mode: str = 'CBC', input_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption._block_cipher_decrypt(ciphertext, key, AES, 16, mode, input_format, iv, padding)
    
    @staticmethod
    def des_encrypt(plaintext: str, key: str, mode: str = 'CBC', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption._block_cipher_encrypt(plaintext, key, DES, 8, mode, output_format, iv, padding)
    
    @staticmethod
    def des_decrypt(ciphertext: str, key: str, mode: str = 'CBC', input_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption._block_cipher_decrypt(ciphertext, key, DES, 8, mode, input_format, iv, padding)
    
    @staticmethod
    def tdes_encrypt(plaintext: str, key: str, mode: str = 'CBC', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption._block_cipher_encrypt(plaintext, key, DES3, 24, mode, output_format, iv, padding)
    
    @staticmethod
    def tdes_decrypt(ciphertext: str, key: str, mode: str = 'CBC', input_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption._block_cipher_decrypt(ciphertext, key, DES3, 24, mode, input_format, iv, padding)
    
    @staticmethod
    def _rc4_ksa(key: bytes) -> list:
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S
    
    @staticmethod
    def _rc4_prga(S: list, data: bytes, drop_bytes: int = 3072) -> bytes:
        i = j = 0
        result = []
        
        for _ in range(drop_bytes):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result)
    
    @staticmethod
    def _rc4_operation(data: bytes, key: bytes) -> bytes:
        S = ModernEncryption._rc4_ksa(key)
        return ModernEncryption._rc4_prga(S, data, drop_bytes=3072)
    
    @staticmethod
    def _standard_rc4_ksa(key: bytes) -> list:
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S
    
    @staticmethod
    def _standard_rc4_prga(S: list, data: bytes) -> bytes:
        i = 0
        j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        return bytes(result)
    
    @staticmethod
    def rc4_encrypt(plaintext: str, key: str, output_format: str = 'base64') -> str:
        key_bytes, salt = ModernEncryption._prepare_key(key, 32)
        nonce = get_random_bytes(8)
        extended_key = key_bytes + nonce
        ciphertext_bytes = ModernEncryption._rc4_operation(plaintext.encode('utf-8'), extended_key)
        return ModernEncryption._format_output(salt + nonce + ciphertext_bytes, output_format)
    
    @staticmethod
    def rc4_decrypt(ciphertext: str, key: str, input_format: str = 'base64') -> str:
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        salt = ciphertext_bytes[:16]
        nonce = ciphertext_bytes[16:24]
        encrypted_data = ciphertext_bytes[24:]
        key_bytes, _ = ModernEncryption._prepare_key(key, 32, salt)
        extended_key = key_bytes + nonce
        plaintext_bytes = ModernEncryption._rc4_operation(encrypted_data, extended_key)
        return plaintext_bytes.decode('utf-8', errors='ignore')
    
    @staticmethod
    def rc4_standard_encrypt(plaintext: str, key: str, output_format: str = 'base64') -> str:
        key_bytes = key.encode('utf-8')
        S = ModernEncryption._standard_rc4_ksa(key_bytes)
        ciphertext_bytes = ModernEncryption._standard_rc4_prga(S, plaintext.encode('utf-8'))
        return ModernEncryption._format_output(ciphertext_bytes, output_format)
    
    @staticmethod
    def rc4_standard_decrypt(ciphertext: str, key: str, input_format: str = 'base64') -> str:
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        key_bytes = key.encode('utf-8')
        S = ModernEncryption._standard_rc4_ksa(key_bytes)
        plaintext_bytes = ModernEncryption._standard_rc4_prga(S, ciphertext_bytes)
        return plaintext_bytes.decode('utf-8', errors='ignore')
    
    @staticmethod
    def rc4_openssl_decrypt(ciphertext: str, key: str, input_format: str = 'base64') -> str:
        from Crypto.Hash import MD5
        
        ciphertext_bytes = ModernEncryption._parse_input(ciphertext, input_format)
        
        if len(ciphertext_bytes) < 16:
            raise ValueError("OpenSSL RC4密文格式错误：长度不足16字节")
        
        salt = ciphertext_bytes[8:16]
        encrypted_data = ciphertext_bytes[16:]
        
        key_bytes = key.encode('utf-8')
        
        d = d_i = b''
        while len(d) < 32:
            md = MD5.new()
            md.update(d_i + key_bytes + salt)
            d_i = md.digest()
            d += d_i
        
        derived_key = d[:32]
        
        S = ModernEncryption._standard_rc4_ksa(derived_key)
        plaintext_bytes = ModernEncryption._standard_rc4_prga(S, encrypted_data)
        return plaintext_bytes.decode('utf-8', errors='ignore')
    
    @staticmethod
    def rc4_openssl_encrypt(plaintext: str, key: str, output_format: str = 'base64') -> str:
        from Crypto.Hash import MD5
        from Crypto.Random import get_random_bytes
        
        salt = get_random_bytes(8)
        
        key_bytes = key.encode('utf-8')
        
        d = d_i = b''
        while len(d) < 32:
            md = MD5.new()
            md.update(d_i + key_bytes + salt)
            d_i = md.digest()
            d += d_i
        
        derived_key = d[:32]
        
        S = ModernEncryption._standard_rc4_ksa(derived_key)
        ciphertext_bytes = ModernEncryption._standard_rc4_prga(S, plaintext.encode('utf-8'))
        
        result = b'Salted__' + salt + ciphertext_bytes
        return ModernEncryption._format_output(result, output_format)
