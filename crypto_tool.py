#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import binascii
import re
import string
from typing import List, Tuple, Dict, Optional
from urllib.parse import quote, unquote
import html
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from base_encoding import BaseEncoding
from encoding_conversion import EncodingConversion
from classical_ciphers import ClassicalCiphers
from modern_encryption import ModernEncryption
from special_encoding import SpecialEncoding
from misc_encoding import MiscEncoding
from hash_functions import HashFunctions
from base_conversion import BaseConversion


class CryptoTool:
    def __init__(self):
        self.algorithms = self._get_all_algorithms()
    
    def _get_all_algorithms(self) -> Dict[str, Dict]:
        return {
            'base': {
                'name': 'Base编码',
                'methods': ['base16', 'base32', 'base36', 'base58', 'base62', 'base64', 'base85', 'base91', 'base92']
            },
            'encoding': {
                'name': '编码转换',
                'methods': ['hex', 'url', 'html', 'escape', 'ascii', 'quoted']
            },
            'classical': {
                'name': '古典密码',
                'methods': ['caesar', 'vigenere', 'railfence', 'rot13', 'atbash', 'affine', 'playfair', 
                           'beaufort', 'porta', 'autokey', 'bifid', 'four', 'gronsfeld', 'keyword', 
                           'runkey', 'simple', 'columnar', 'a1z26', 'adfgx', 'adfgvx']
            },
            'modern': {
                'name': '现代加密',
                'methods': ['aes', 'des', '3des', 'rc4']
            },
            'special': {
                'name': '特殊编码',
                'methods': ['morse', 'tapcode', 'pigpen', 'baconian']
            },
            'misc': {
                'name': '杂项工具',
                'methods': ['xxencode', 'uuencode', 'jsfuck', 'brainfuck', 'bubble', 'aaencode', 'jjencode', 'ppencode']
            },
            'hash': {
                'name': '哈希计算',
                'methods': ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'ripemd', 'ripemd160']
            },
            'convert': {
                'name': '进制转换',
                'methods': ['binary', 'octal', 'decimal', 'hexadecimal']
            }
        }
    
    def get_algorithm_info(self) -> Dict[str, str]:
        return {
            'Base16': 'Base16编码是一种将二进制数据转换为16进制字符的编码方式，使用0-9和A-F字符。',
            'Base32': 'Base32编码是一种将二进制数据转换为32进制字符的编码方式，使用A-Z和2-7字符。',
            'Base36': 'Base36编码是一种将二进制数据转换为36进制字符的编码方式，使用0-9和A-Z字符。',
            'Base58': 'Base58编码是一种用于比特币地址的编码方式，去除了容易混淆的字符。',
            'Base62': 'Base62编码是一种将二进制数据转换为62进制字符的编码方式，使用0-9、A-Z和a-z字符。',
            'Base64': 'Base64编码是一种将二进制数据转换为64进制字符的编码方式，使用A-Z、a-z、0-9和+、/字符。',
            'Base85': 'Base85编码是一种将二进制数据转换为85进制字符的编码方式，比Base64更高效。',
            'Base91': 'Base91编码是一种将二进制数据转换为91进制字符的编码方式，使用ASCII可打印字符。',
            'Base92': 'Base92编码是一种将二进制数据转换为92进制字符的编码方式。',
            'Hex': 'Hex编码（十六进制）将每个字节转换为两个十六进制字符。',
            'URL编码': 'URL编码将特殊字符转换为%XX格式，用于在URL中传输。',
            'HTML编码': 'HTML编码将特殊字符转换为HTML实体，如&变为&amp;。',
            'Escape编码': 'Escape编码将特殊字符转换为转义序列。',
            'ASCII编码': 'ASCII编码将字符转换为ASCII码数值。',
            'Quoted编码': 'Quoted-printable编码用于电子邮件，将非ASCII字符转换为=XX格式。',
            'Caesar密码': 'Caesar密码是一种简单的替换密码，将字母表中的每个字母移动固定位数。',
            'Vigenère密码': 'Vigenère密码是一种多表替换密码，使用关键词进行加密。',
            'ROT13': 'ROT13是Caesar密码的一种特殊形式，将字母移动13位。',
            'Atbash密码': 'Atbash密码是一种替换密码，将字母表反转。',
            'Affine密码': 'Affine密码是一种使用数学函数的替换密码，公式为E(x) = (ax + b) mod 26。',
            'Railfence密码': 'Railfence密码是一种换位密码，将文本按锯齿形排列后按行读取。',
            'A1Z26': 'A1Z26密码将字母转换为对应的数字，A=1, B=2, ..., Z=26。',
            'Playfair密码': 'Playfair密码是一种使用5x5矩阵的双字母替换密码。',
            'Beaufort密码': 'Beaufort密码是一种多表替换密码，类似于Vigenère密码但使用不同的加密方式。',
            'Porta密码': 'Porta密码是一种多表替换密码，使用关键词进行加密。',
            'Autokey密码': 'Autokey密码是一种使用密钥和明文本身作为密钥的密码。',
            'Bifid密码': 'Bifid密码是一种使用Polybius方阵的替换密码。',
            'Four-Square密码': 'Four-Square密码是一种使用四个5x5矩阵的替换密码。',
            'Gronsfeld密码': 'Gronsfeld密码是一种使用数字密钥的变体Vigenère密码。',
            'Keyword密码': 'Keyword密码是一种使用关键词创建替换表的替换密码。',
            'Running Key密码': 'Running Key密码是一种使用长密钥（如书籍文本）的密码。',
            'Simple密码': 'Simple密码是一种简单的替换密码，使用关键词创建替换表。',
            'Columnar密码': 'Columnar密码是一种换位密码，将文本按列排列后按行读取。',
            'ADFGX密码': 'ADFGX密码是一种使用5x5方阵和ADFGX字母的替换密码。',
            'ADFGVX密码': 'ADFGVX密码是一种使用6x6方阵和ADFGVX字母的替换密码。',
            'AES加密': 'AES（高级加密标准）是一种对称加密算法，支持128、192、256位密钥。',
            'DES加密': 'DES（数据加密标准）是一种对称加密算法，使用56位密钥。',
            '3DES加密': '3DES（三重DES）是DES的改进版本，应用三次DES加密。',
            'RC4加密': 'RC4是一种流密码算法，虽然曾经广泛使用，但现在被认为不够安全。',
            'Morse密码': 'Morse密码使用点和划的组合来表示字母和数字。',
            'Tapcode': 'Tapcode是一种敲击密码，用于监狱中通过敲击传递信息。',
            '猪圈密码': '猪圈密码是一种使用图形符号的替换密码。',
            'Baconian密码': 'Baconian密码是一种使用A和B两种字母的替换密码。',
            'XXencode': 'XXencode是一种将二进制数据转换为可打印ASCII字符的编码方式。',
            'UUencode': 'UUencode是一种将二进制数据转换为可打印ASCII字符的编码方式，用于电子邮件。',
            'Brainfuck': 'Brainfuck是一种极简主义的编程语言，也可以用于编码。',
            '二进制': '二进制转换将数字转换为二进制表示（0和1）。',
            '八进制': '八进制转换将数字转换为八进制表示（0-7）。',
            '十进制': '十进制转换将数字转换为十进制表示（0-9）。',
            '十六进制': '十六进制转换将数字转换为十六进制表示（0-9和A-F）。',
            'MD5': 'MD5是一种哈希算法，产生128位哈希值，已不再推荐用于安全用途。',
            'SHA1': 'SHA1是一种哈希算法，产生160位哈希值，已不再推荐用于安全用途。',
            'SHA256': 'SHA256是一种哈希算法，产生256位哈希值，广泛用于安全应用。',
            'SHA384': 'SHA384是一种哈希算法，产生384位哈希值。',
            'SHA512': 'SHA512是一种哈希算法，产生512位哈希值。',
            'RIPEMD160': 'RIPEMD160是一种哈希算法，产生160位哈希值。'
        }
    
    def auto_detect(self, ciphertext: str, key: str = None) -> List[Tuple[str, str, str]]:
        results = []
        
        if not ciphertext:
            return results
        
        ciphertext = ciphertext.strip()
        
        all_methods = [
            ('base64', 'Base64编码', lambda: self.base64_decode(ciphertext)),
            ('base32', 'Base32编码', lambda: self.base32_decode(ciphertext)),
            ('hex', 'Hex编码', lambda: self.hex_decode(ciphertext)),
            ('url', 'URL编码', lambda: self.url_decode(ciphertext)),
            ('morse', '莫尔斯电码', lambda: self.morse_decode(ciphertext)),
            ('a1z26', 'A1Z26密码', lambda: self.a1z26_decode(ciphertext)),
            ('rot13', 'ROT13密码', lambda: self.rot13_decrypt(ciphertext)),
            ('atbash', '埃特巴什码', lambda: self.atbash_decrypt(ciphertext)),
            ('baconian', '培根密码', lambda: self.baconian_decode(ciphertext)),
            ('tapcode', '敲击码', lambda: self.tapcode_decode(ciphertext)),
            ('base58', 'Base58编码', lambda: self.base58_decode(ciphertext)),
            ('base62', 'Base62编码', lambda: self.base62_decode(ciphertext)),
            ('base91', 'Base91编码', lambda: self.base91_decode(ciphertext)),
            ('base85', 'Base85编码', lambda: self.base85_decode(ciphertext)),
            ('base16', 'Base16编码', lambda: self.base16_decode(ciphertext)),
            ('base36', 'Base36编码', lambda: self.base36_decode(ciphertext)),
            ('xxencode', 'XXencode编码', lambda: self.xxencode_decode(ciphertext)),
            ('uuencode', 'UUencode编码', lambda: self.uuencode_decode(ciphertext)),
            ('html', 'HTML编码', lambda: self.html_decode(ciphertext)),
            ('quoted', 'Quoted-printable编码', lambda: self.quoted_decode(ciphertext)),
            ('brainfuck', 'Brainfuck编码', lambda: self.brainfuck_decode(ciphertext)),
        ]
        
        for method, name, decrypt_func in all_methods:
            try:
                if method == 'bubble' and not self._is_bubble(ciphertext):
                    continue
                result = decrypt_func()
                if result and len(result) > 0:
                    results.append((method, name, result))
            except:
                pass
        
        if key and key.strip():
            key = key.strip()
            
            try:
                if key.isdigit():
                    shift = int(key)
                    if 1 <= shift <= 25:
                        try:
                            result = self.caesar_decrypt(ciphertext, shift)
                            if result and result.isprintable() and len(result) > 0:
                                results.append(('caesar', f'Caesar密码(移位{shift})', result))
                        except:
                            pass
                else:
                    try:
                        result = self.caesar_decrypt(ciphertext, key)
                        if result and result.isprintable() and len(result) > 0:
                            results.append(('caesar', f'Caesar密码(密钥:{key})', result))
                    except:
                        pass
            except:
                pass
            
            try:
                result = self.vigenere_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('vigenere', f'Vigenère密码(密钥:{key})', result))
            except:
                pass
            
            try:
                if ',' in key:
                    parts = key.split(',')
                    if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                        a = int(parts[0].strip())
                        b = int(parts[1].strip())
                        try:
                            result = self.affine_decrypt(ciphertext, a, b)
                            if result and result.isprintable() and len(result) > 0:
                                results.append(('affine', f'Affine密码(a={a},b={b})', result))
                        except:
                            pass
            except:
                pass
            
            try:
                result = self.playfair_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('playfair', f'Playfair密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.beaufort_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('beaufort', f'Beaufort密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.porta_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('porta', f'Porta密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.autokey_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('autokey', f'Autokey密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.bifid_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('bifid', f'Bifid密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.four_square_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('four', f'Four-Square密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.gronsfeld_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('gronsfeld', f'Gronsfeld密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.keyword_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('keyword', f'Keyword密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.running_key_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('runkey', f'Running Key密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.simple_substitution_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('simple', f'Simple Substitution密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.columnar_transposition_decrypt(ciphertext, key)
                if result and result.isprintable() and len(result) > 0:
                    results.append(('columnar', f'Columnar Transposition密码(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.aes_decrypt(ciphertext, key)
                if result and len(result) > 0:
                    results.append(('aes', f'AES加密(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.des_decrypt(ciphertext, key)
                if result and len(result) > 0:
                    results.append(('des', f'DES加密(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.triple_des_decrypt(ciphertext, key)
                if result and len(result) > 0:
                    results.append(('3des', f'3DES加密(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.rc4_decrypt(ciphertext, key, output_format='base64')
                if result and len(result) > 0:
                    results.append(('rc4', f'RC4加密(密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.rc4_decrypt(ciphertext, key, output_format='hex')
                if result and len(result) > 0:
                    results.append(('rc4', f'RC4加密(密钥:{key},Hex格式)', result))
            except:
                pass
            
            try:
                result = self.rc4_decrypt(ciphertext, key, output_format='plain')
                if result and len(result) > 0:
                    results.append(('rc4', f'RC4加密(密钥:{key},纯文本)', result))
            except:
                pass
            
            try:
                result = self.rc4_openssl_decrypt(ciphertext, key, output_format='base64')
                if result and len(result) > 0:
                    results.append(('rc4_openssl', f'RC4加密(OpenSSL格式,密钥:{key})', result))
            except:
                pass
            
            try:
                result = self.rc4_openssl_decrypt(ciphertext, key, output_format='hex')
                if result and len(result) > 0:
                    results.append(('rc4_openssl', f'RC4加密(OpenSSL格式,密钥:{key},Hex)', result))
            except:
                pass
        else:
            try:
                for shift in range(1, 26):
                    try:
                        result = self.caesar_decrypt(ciphertext, shift)
                        if result and result.isprintable() and len(result) > 0:
                            results.append(('caesar', f'Caesar密码(移位{shift})', result))
                            break
                    except:
                        pass
            except:
                pass
            
            try:
                common_keys = ['KEY', 'SECRET', 'PASSWORD', 'ABC', 'XYZ']
                for key in common_keys:
                    try:
                        result = self.vigenere_decrypt(ciphertext, key)
                        if result and result.isprintable() and len(result) > 0:
                            results.append(('vigenere', f'Vigenère密码(密钥:{key})', result))
                            break
                    except:
                        pass
            except:
                pass
        
        return results
    
    def _is_base64(self, text: str) -> bool:
        if len(text) < 4:
            return False
        pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        if not re.match(pattern, text):
            return False
        try:
            decoded = base64.b64decode(text)
            return True
        except:
            return False
    
    def _is_base32(self, text: str) -> bool:
        if len(text) < 2:
            return False
        pattern = r'^[A-Z2-7]+=*$'
        if not re.match(pattern, text.upper()):
            return False
        try:
            decoded = base64.b32decode(text)
            return True
        except:
            return False
    
    def _is_base16(self, text: str) -> bool:
        if len(text) < 2:
            return False
        pattern = r'^[0-9A-Fa-f]+$'
        if not re.match(pattern, text):
            return False
        try:
            decoded = base64.b16decode(text)
            return True
        except:
            return False
    
    def _is_base36(self, text: str) -> bool:
        if len(text) < 1:
            return False
        pattern = r'^[0-9A-Za-z]+$'
        return bool(re.match(pattern, text))
    
    def _is_base58(self, text: str) -> bool:
        if len(text) < 1:
            return False
        base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        return all(c in base58_chars for c in text)
    
    def _is_base62(self, text: str) -> bool:
        if len(text) < 1:
            return False
        base62_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        return all(c in base62_chars for c in text)
    
    def _is_base85(self, text: str) -> bool:
        if len(text) < 2:
            return False
        pattern = r'^[0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]+$'
        return bool(re.match(pattern, text))
    
    def _is_base91(self, text: str) -> bool:
        if len(text) < 2:
            return False
        base91_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~"'
        return all(c in base91_chars for c in text)
    
    def _is_hex(self, text: str) -> bool:
        if len(text) % 2 != 0:
            return False
        pattern = r'^[0-9A-Fa-f]+$'
        return bool(re.match(pattern, text))
    
    def _is_bubble(self, text: str) -> bool:
        if len(text) < 5:
            return False
        if not text.startswith('x') or not text.endswith('x'):
            return False
        
        content = text[1:-1]
        if not content:
            return True
        
        parts = content.split('-')
        
        for i, part in enumerate(parts):
            if len(part) == 0:
                continue
            
            is_first = (i == 0)
            is_last = (i == len(parts) - 1)
            
            if is_first or is_last:
                if len(part) != 4 and len(part) != 5:
                    return False
            else:
                if len(part) != 5:
                    return False
        
        return True
    
    def _is_url_encoded(self, text: str) -> bool:
        return '%' in text and re.search(r'%[0-9A-Fa-f]{2}', text)
    
    def _is_html_encoded(self, text: str) -> bool:
        return bool(re.search(r'&[a-zA-Z]+;', text) or re.search(r'&#\d+;', text))
    
    def _is_quoted_printable(self, text: str) -> bool:
        return '=' in text and re.search(r'=[0-9A-Fa-f]{2}', text)
    
    def _is_morse(self, text: str) -> bool:
        morse_chars = set('.- /')
        return all(c in morse_chars for c in text) and ('.' in text or '-' in text)
    
    def _is_a1z26(self, text: str) -> bool:
        return bool(re.match(r'^(\d+\s*)+$', text)) and all(1 <= int(x) <= 26 for x in text.split() if x)
    
    def _is_rot13(self, text: str) -> bool:
        try:
            decoded = self.rot13_decrypt(text)
            return decoded.isprintable() and len(decoded) > 0
        except:
            return False
    
    def _is_atbash(self, text: str) -> bool:
        try:
            decoded = self.atbash_decrypt(text)
            return decoded.isprintable() and len(decoded) > 0
        except:
            return False
    
    def _is_baconian(self, text: str) -> bool:
        baconian_chars = set('ABab')
        return all(c in baconian_chars for c in text) and len(text) % 5 == 0
    
    def _is_tapcode(self, text: str) -> bool:
        return bool(re.match(r'^(\d-\d\s*)+$', text))
    
    def _is_xxencode(self, text: str) -> bool:
        if len(text) < 2:
            return False
        xxencode_chars = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        return all(c in xxencode_chars for c in text) and text.endswith('+')
    
    def _is_uuencode(self, text: str) -> bool:
        return bool(re.match(r'^[M`-z]', text)) and len(text) > 0
    
    def encrypt(self, method: str, plaintext: str, key: str = '', **kwargs) -> str:
        method = method.lower()
        
        if method in ['base16', 'base32', 'base36', 'base58', 'base62', 'base64', 'base85', 'base91', 'base92']:
            return self._base_encrypt(method, plaintext)
        elif method in ['hex', 'url', 'html', 'escape', 'ascii', 'quoted']:
            return self._encoding_encrypt(method, plaintext)
        elif method in ['caesar', 'vigenere', 'railfence', 'rot13', 'atbash', 'affine', 'playfair', 
                       'beaufort', 'porta', 'autokey', 'bifid', 'four', 'gronsfeld', 'keyword', 
                       'runkey', 'simple', 'columnar', 'a1z26', 'adfgx', 'adfgvx']:
            return self._classical_encrypt(method, plaintext, key, **kwargs)
        elif method in ['aes', 'des', '3des', 'rc4']:
            return self._modern_encrypt(method, plaintext, key, **kwargs)
        elif method in ['morse', 'tapcode', 'pigpen', 'baconian']:
            return self._special_encrypt(method, plaintext, **kwargs)
        elif method in ['xxencode', 'uuencode', 'jsfuck', 'brainfuck', 'bubble', 'aaencode', 'jjencode', 'ppencode']:
            return self._misc_encrypt(method, plaintext)
        elif method in ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'ripemd', 'ripemd160']:
            return self._hash_encrypt(method, plaintext)
        elif method in ['binary', 'octal', 'decimal', 'hexadecimal']:
            return self._convert_encrypt(method, plaintext, **kwargs)
        else:
            raise ValueError(f"不支持的加密方法: {method}")
    
    def decrypt(self, method: str, ciphertext: str, key: str = '', **kwargs) -> str:
        method = method.lower()
        
        if method in ['base16', 'base32', 'base36', 'base58', 'base62', 'base64', 'base85', 'base91', 'base92']:
            return self._base_decrypt(method, ciphertext)
        elif method in ['hex', 'url', 'html', 'escape', 'ascii', 'quoted']:
            return self._encoding_decrypt(method, ciphertext)
        elif method in ['caesar', 'vigenere', 'railfence', 'rot13', 'atbash', 'affine', 'playfair', 
                       'beaufort', 'porta', 'autokey', 'bifid', 'four', 'gronsfeld', 'keyword', 
                       'runkey', 'simple', 'columnar', 'a1z26', 'adfgx', 'adfgvx']:
            return self._classical_decrypt(method, ciphertext, key, **kwargs)
        elif method in ['aes', 'des', '3des', 'rc4']:
            return self._modern_decrypt(method, ciphertext, key, **kwargs)
        elif method in ['morse', 'tapcode', 'pigpen', 'baconian']:
            return self._special_decrypt(method, ciphertext, **kwargs)
        elif method in ['xxencode', 'uuencode', 'jsfuck', 'brainfuck', 'bubble', 'aaencode', 'jjencode', 'ppencode']:
            return self._misc_decrypt(method, ciphertext)
        elif method in ['binary', 'octal', 'decimal', 'hexadecimal']:
            return self._convert_decrypt(method, ciphertext, **kwargs)
        else:
            raise ValueError(f"不支持的解密方法: {method}")
    
    def _base_encrypt(self, method: str, plaintext: str) -> str:
        method = method.lower()
        method_map = {
            'base16': self.base16_encode,
            'base32': self.base32_encode,
            'base36': self.base36_encode,
            'base58': self.base58_encode,
            'base62': self.base62_encode,
            'base64': self.base64_encode,
            'base85': self.base85_encode,
            'base91': self.base91_encode,
            'base92': self.base92_encode
        }
        if method not in method_map:
            raise ValueError(f"不支持的Base编码: {method}")
        return method_map[method](plaintext)
    
    def _base_decrypt(self, method: str, ciphertext: str) -> str:
        method = method.lower()
        method_map = {
            'base16': self.base16_decode,
            'base32': self.base32_decode,
            'base36': self.base36_decode,
            'base58': self.base58_decode,
            'base62': self.base62_decode,
            'base64': self.base64_decode,
            'base85': self.base85_decode,
            'base91': self.base91_decode,
            'base92': self.base92_decode
        }
        if method not in method_map:
            raise ValueError(f"不支持的Base编码: {method}")
        return method_map[method](ciphertext)
    
    def _encoding_encrypt(self, method: str, plaintext: str) -> str:
        method = method.lower()
        method_map = {
            'hex': self.hex_encode,
            'url': self.url_encode,
            'html': self.html_encode,
            'escape': self.escape_encode,
            'ascii': self.ascii_encode,
            'quoted': self.quoted_encode
        }
        if method not in method_map:
            raise ValueError(f"不支持的编码: {method}")
        return method_map[method](plaintext)
    
    def _encoding_decrypt(self, method: str, ciphertext: str) -> str:
        method = method.lower()
        method_map = {
            'hex': self.hex_decode,
            'url': self.url_decode,
            'html': self.html_decode,
            'escape': self.escape_decode,
            'ascii': self.ascii_decode,
            'quoted': self.quoted_decode
        }
        if method not in method_map:
            raise ValueError(f"不支持的编码: {method}")
        return method_map[method](ciphertext)
    
    def _classical_encrypt(self, method: str, plaintext: str, key: str = '', **kwargs) -> str:
        method = method.lower()
        method_map = {
            'caesar': lambda: self.caesar_encrypt(plaintext, kwargs.get('shift', 3)),
            'vigenere': lambda: self.vigenere_encrypt(plaintext, key),
            'railfence': lambda: self.railfence_encrypt(plaintext, kwargs.get('rails', 3)),
            'rot13': lambda: self.rot13_encrypt(plaintext),
            'atbash': lambda: self.atbash_encrypt(plaintext),
            'affine': lambda: self.affine_encrypt(plaintext, kwargs.get('a', 5), kwargs.get('b', 8)),
            'playfair': lambda: self.playfair_encrypt(plaintext, key),
            'beaufort': lambda: self.beaufort_encrypt(plaintext, key),
            'porta': lambda: self.porta_encrypt(plaintext, key),
            'autokey': lambda: self.autokey_encrypt(plaintext, key),
            'bifid': lambda: self.bifid_encrypt(plaintext, key),
            'four': lambda: self.four_encrypt(plaintext, key),
            'gronsfeld': lambda: self.gronsfeld_encrypt(plaintext, key),
            'keyword': lambda: self.keyword_encrypt(plaintext, key),
            'runkey': lambda: self.runkey_encrypt(plaintext, key),
            'simple': lambda: self.simple_encrypt(plaintext, key),
            'columnar': lambda: self.columnar_encrypt(plaintext, key),
            'a1z26': lambda: self.a1z26_encrypt(plaintext),
            'adfgx': lambda: self.adfgx_encrypt(plaintext, key),
            'adfgvx': lambda: self.adfgvx_encrypt(plaintext, key)
        }
        if method not in method_map:
            raise ValueError(f"不支持的古典密码: {method}")
        return method_map[method]()
    
    def _classical_decrypt(self, method: str, ciphertext: str, key: str = '', **kwargs) -> str:
        method = method.lower()
        method_map = {
            'caesar': lambda: self.caesar_decrypt(ciphertext, kwargs.get('shift', 3)),
            'vigenere': lambda: self.vigenere_decrypt(ciphertext, key),
            'railfence': lambda: self.railfence_decrypt(ciphertext, kwargs.get('rails', 3)),
            'rot13': lambda: self.rot13_decrypt(ciphertext),
            'atbash': lambda: self.atbash_decrypt(ciphertext),
            'affine': lambda: self.affine_decrypt(ciphertext, kwargs.get('a', 5), kwargs.get('b', 8)),
            'playfair': lambda: self.playfair_decrypt(ciphertext, key),
            'beaufort': lambda: self.beaufort_decrypt(ciphertext, key),
            'porta': lambda: self.porta_decrypt(ciphertext, key),
            'autokey': lambda: self.autokey_decrypt(ciphertext, key),
            'bifid': lambda: self.bifid_decrypt(ciphertext, key),
            'four': lambda: self.four_decrypt(ciphertext, key),
            'gronsfeld': lambda: self.gronsfeld_decrypt(ciphertext, key),
            'keyword': lambda: self.keyword_decrypt(ciphertext, key),
            'runkey': lambda: self.runkey_decrypt(ciphertext, key),
            'simple': lambda: self.simple_decrypt(ciphertext, key),
            'columnar': lambda: self.columnar_decrypt(ciphertext, key),
            'a1z26': lambda: self.a1z26_decrypt(ciphertext),
            'adfgx': lambda: self.adfgx_decrypt(ciphertext, key),
            'adfgvx': lambda: self.adfgvx_decrypt(ciphertext, key)
        }
        if method not in method_map:
            raise ValueError(f"不支持的古典密码: {method}")
        return method_map[method]()
    
    def _modern_encrypt(self, method: str, plaintext: str, key: str, **kwargs) -> str:
        method = method.lower()
        mode = kwargs.get('mode', 'CBC')
        output_format = kwargs.get('output_format', 'base64')
        iv = kwargs.get('iv', None)
        padding = kwargs.get('padding', 'pkcs7')
        method_map = {
            'aes': lambda: self.aes_encrypt(plaintext, key, mode, output_format, iv, padding),
            'des': lambda: self.des_encrypt(plaintext, key, mode, output_format, iv, padding),
            '3des': lambda: self.tdes_encrypt(plaintext, key, mode, output_format, iv, padding),
            'rc4': lambda: self.rc4_openssl_encrypt(plaintext, key, output_format)
        }
        if method not in method_map:
            raise ValueError(f"不支持的现代加密: {method}")
        return method_map[method]()
    
    def _modern_decrypt(self, method: str, ciphertext: str, key: str, **kwargs) -> str:
        method = method.lower()
        mode = kwargs.get('mode', 'CBC')
        output_format = kwargs.get('output_format', 'base64')
        iv = kwargs.get('iv', None)
        padding = kwargs.get('padding', 'pkcs7')
        method_map = {
            'aes': lambda: self.aes_decrypt(ciphertext, key, mode, output_format, iv, padding),
            'des': lambda: self.des_decrypt(ciphertext, key, mode, output_format, iv, padding),
            '3des': lambda: self.tdes_decrypt(ciphertext, key, mode, output_format, iv, padding),
            'rc4': lambda: self.rc4_openssl_decrypt(ciphertext, key, output_format)
        }
        if method not in method_map:
            raise ValueError(f"不支持的现代加密: {method}")
        return method_map[method]()
    
    def _special_encrypt(self, method: str, plaintext: str, **kwargs) -> str:
        method = method.lower()
        method_map = {
            'morse': self.morse_encode,
            'tapcode': self.tapcode_encode,
            'pigpen': self.pigpen_encode,
            'baconian': self.baconian_encode
        }
        if method not in method_map:
            raise ValueError(f"不支持的特殊编码: {method}")
        return method_map[method](plaintext)
    
    def _special_decrypt(self, method: str, ciphertext: str, **kwargs) -> str:
        method = method.lower()
        method_map = {
            'morse': self.morse_decode,
            'tapcode': self.tapcode_decode,
            'pigpen': self.pigpen_decode,
            'baconian': self.baconian_decode
        }
        if method not in method_map:
            raise ValueError(f"不支持的特殊编码: {method}")
        return method_map[method](ciphertext)
    
    def _misc_encrypt(self, method: str, plaintext: str) -> str:
        method = method.lower()
        method_map = {
            'xxencode': self.xxencode_encode,
            'uuencode': self.uuencode_encode,
            'jsfuck': self.jsfuck_encode,
            'brainfuck': self.brainfuck_encode,
            'bubble': self.bubble_encode,
            'aaencode': self.aaencode_encode,
            'jjencode': self.jjencode_encode,
            'ppencode': self.ppencode_encode
        }
        if method not in method_map:
            raise ValueError(f"不支持的杂项编码: {method}")
        return method_map[method](plaintext)
    
    def _misc_decrypt(self, method: str, ciphertext: str) -> str:
        method = method.lower()
        method_map = {
            'xxencode': self.xxencode_decode,
            'uuencode': self.uuencode_decode,
            'jsfuck': self.jsfuck_decode,
            'brainfuck': self.brainfuck_decode,
            'bubble': self.bubble_decode,
            'aaencode': self.aaencode_decode,
            'jjencode': self.jjencode_decode,
            'ppencode': self.ppencode_decode
        }
        if method not in method_map:
            raise ValueError(f"不支持的杂项编码: {method}")
        return method_map[method](ciphertext)
    
    def _hash_encrypt(self, method: str, plaintext: str) -> str:
        method = method.lower()
        method_map = {
            'md5': self.md5_hash,
            'sha1': self.sha1_hash,
            'sha256': self.sha256_hash,
            'sha384': self.sha384_hash,
            'sha512': self.sha512_hash,
            'ripemd': self.ripemd_hash,
            'ripemd160': self.ripemd160_hash
        }
        if method not in method_map:
            raise ValueError(f"不支持的哈希算法: {method}")
        return method_map[method](plaintext)
    
    def _convert_encrypt(self, method: str, plaintext: str, **kwargs) -> str:
        method = method.lower()
        method_map = {
            'binary': self.binary_encode,
            'octal': self.octal_encode,
            'decimal': self.decimal_encode,
            'hexadecimal': self.hexadecimal_encode
        }
        if method not in method_map:
            raise ValueError(f"不支持的进制转换: {method}")
        return method_map[method](plaintext)
    
    def _convert_decrypt(self, method: str, ciphertext: str, **kwargs) -> str:
        method = method.lower()
        method_map = {
            'binary': self.binary_decode,
            'octal': self.octal_decode,
            'decimal': self.decimal_decode,
            'hexadecimal': self.hexadecimal_decode
        }
        if method not in method_map:
            raise ValueError(f"不支持的进制转换: {method}")
        return method_map[method](ciphertext)

    def base16_encode(self, text: str) -> str:
        return BaseEncoding.base16_encode(text)

    def base16_decode(self, text: str) -> str:
        return BaseEncoding.base16_decode(text)

    def base32_encode(self, text: str) -> str:
        return BaseEncoding.base32_encode(text)

    def base32_decode(self, text: str) -> str:
        return BaseEncoding.base32_decode(text)

    def base36_encode(self, text: str) -> str:
        return BaseEncoding.base36_encode(text)

    def base36_decode(self, text: str) -> str:
        return BaseEncoding.base36_decode(text)

    def base58_encode(self, text: str) -> str:
        return BaseEncoding.base58_encode(text)

    def base58_decode(self, text: str) -> str:
        return BaseEncoding.base58_decode(text)

    def base62_encode(self, text: str) -> str:
        return BaseEncoding.base62_encode(text)

    def base62_decode(self, text: str) -> str:
        return BaseEncoding.base62_decode(text)

    def base64_encode(self, text: str) -> str:
        return BaseEncoding.base64_encode(text)

    def base64_decode(self, text: str) -> str:
        return BaseEncoding.base64_decode(text)

    def base85_encode(self, text: str) -> str:
        return BaseEncoding.base85_encode(text)

    def base85_decode(self, text: str) -> str:
        return BaseEncoding.base85_decode(text)

    def base91_encode(self, text: str) -> str:
        return BaseEncoding.base91_encode(text)

    def base91_decode(self, text: str) -> str:
        return BaseEncoding.base91_decode(text)

    def base92_encode(self, text: str) -> str:
        return BaseEncoding.base92_encode(text)

    def base92_decode(self, text: str) -> str:
        return BaseEncoding.base92_decode(text)

    def hex_encode(self, text: str) -> str:
        return EncodingConversion.hex_encode(text)

    def hex_decode(self, text: str) -> str:
        return EncodingConversion.hex_decode(text)

    def url_encode(self, text: str) -> str:
        return EncodingConversion.url_encode(text)

    def url_decode(self, text: str) -> str:
        return EncodingConversion.url_decode(text)

    def html_encode(self, text: str) -> str:
        return EncodingConversion.html_encode(text)

    def html_decode(self, text: str) -> str:
        return EncodingConversion.html_decode(text)

    def escape_encode(self, text: str) -> str:
        return EncodingConversion.escape_encode(text)

    def escape_decode(self, text: str) -> str:
        return EncodingConversion.escape_decode(text)

    def ascii_encode(self, text: str) -> str:
        return EncodingConversion.ascii_encode(text)

    def ascii_decode(self, text: str) -> str:
        return EncodingConversion.ascii_decode(text)

    def quoted_encode(self, text: str) -> str:
        return EncodingConversion.quoted_encode(text)

    def quoted_decode(self, text: str) -> str:
        return EncodingConversion.quoted_decode(text)

    def caesar_encrypt(self, text: str, shift: int = 3) -> str:
        return ClassicalCiphers.caesar_encrypt(text, shift)

    def caesar_decrypt(self, text: str, shift: int = 3) -> str:
        return ClassicalCiphers.caesar_decrypt(text, shift)

    def vigenere_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.vigenere_encrypt(text, key)

    def vigenere_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.vigenere_decrypt(text, key)

    def railfence_encrypt(self, text: str, rails: int = 3) -> str:
        return ClassicalCiphers.railfence_encrypt(text, rails)

    def railfence_decrypt(self, text: str, rails: int = 3) -> str:
        return ClassicalCiphers.railfence_decrypt(text, rails)

    def rot13_encrypt(self, text: str) -> str:
        return ClassicalCiphers.rot13_encrypt(text)

    def rot13_decrypt(self, text: str) -> str:
        return ClassicalCiphers.rot13_decrypt(text)

    def atbash_encrypt(self, text: str) -> str:
        return ClassicalCiphers.atbash_encrypt(text)

    def atbash_decrypt(self, text: str) -> str:
        return ClassicalCiphers.atbash_decrypt(text)

    def affine_encrypt(self, text: str, a: int = 5, b: int = 8) -> str:
        return ClassicalCiphers.affine_encrypt(text, a, b)

    def affine_decrypt(self, text: str, a: int = 5, b: int = 8) -> str:
        return ClassicalCiphers.affine_decrypt(text, a, b)

    def playfair_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.playfair_encrypt(text, key)

    def playfair_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.playfair_decrypt(text, key)

    def beaufort_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.beaufort_encrypt(text, key)

    def beaufort_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.beaufort_decrypt(text, key)

    def porta_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.porta_encrypt(text, key)

    def porta_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.porta_decrypt(text, key)

    def autokey_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.autokey_encrypt(text, key)

    def autokey_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.autokey_decrypt(text, key)

    def bifid_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.bifid_encrypt(text, key)

    def bifid_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.bifid_decrypt(text, key)

    def four_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.four_encrypt(text, key)

    def four_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.four_decrypt(text, key)

    def gronsfeld_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.gronsfeld_encrypt(text, key)

    def gronsfeld_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.gronsfeld_decrypt(text, key)

    def keyword_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.keyword_encrypt(text, key)

    def keyword_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.keyword_decrypt(text, key)

    def runkey_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.runkey_encrypt(text, key)

    def runkey_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.runkey_decrypt(text, key)

    def simple_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.simple_encrypt(text, key)

    def simple_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.simple_decrypt(text, key)

    def columnar_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.columnar_encrypt(text, key)

    def columnar_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.columnar_decrypt(text, key)

    def a1z26_encrypt(self, text: str) -> str:
        return ClassicalCiphers.a1z26_encrypt(text)

    def a1z26_decrypt(self, text: str) -> str:
        return ClassicalCiphers.a1z26_decrypt(text)

    def a1z26_encode(self, text: str) -> str:
        return self.a1z26_encrypt(text)

    def a1z26_decode(self, text: str) -> str:
        return self.a1z26_decrypt(text)

    def adfgx_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.adfgx_encrypt(text, key)

    def adfgx_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.adfgx_decrypt(text, key)

    def adfgvx_encrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.adfgvx_encrypt(text, key)

    def adfgvx_decrypt(self, text: str, key: str) -> str:
        return ClassicalCiphers.adfgvx_decrypt(text, key)

    def aes_encrypt(self, plaintext: str, key: str, mode: str = 'ECB', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption.aes_encrypt(plaintext, key, mode, output_format, iv, padding)

    def aes_decrypt(self, ciphertext: str, key: str, mode: str = 'ECB', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption.aes_decrypt(ciphertext, key, mode, output_format, iv, padding)

    def des_encrypt(self, plaintext: str, key: str, mode: str = 'ECB', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption.des_encrypt(plaintext, key, mode, output_format, iv, padding)

    def des_decrypt(self, ciphertext: str, key: str, mode: str = 'ECB', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption.des_decrypt(ciphertext, key, mode, output_format, iv, padding)

    def tdes_encrypt(self, plaintext: str, key: str, mode: str = 'ECB', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption.tdes_encrypt(plaintext, key, mode, output_format, iv, padding)

    def tdes_decrypt(self, ciphertext: str, key: str, mode: str = 'ECB', output_format: str = 'base64', iv: str = None, padding: str = 'pkcs7') -> str:
        return ModernEncryption.tdes_decrypt(ciphertext, key, mode, output_format, iv, padding)

    def rc4_encrypt(self, plaintext: str, key: str, output_format: str = 'base64') -> str:
        return ModernEncryption.rc4_standard_encrypt(plaintext, key, output_format)

    def rc4_decrypt(self, ciphertext: str, key: str, output_format: str = 'base64') -> str:
        return ModernEncryption.rc4_standard_decrypt(ciphertext, key, output_format)
    
    def rc4_openssl_encrypt(self, plaintext: str, key: str, output_format: str = 'base64') -> str:
        return ModernEncryption.rc4_openssl_encrypt(plaintext, key, output_format)
    
    def rc4_openssl_decrypt(self, ciphertext: str, key: str, output_format: str = 'base64') -> str:
        return ModernEncryption.rc4_openssl_decrypt(ciphertext, key, output_format)

    def morse_encode(self, text: str) -> str:
        return SpecialEncoding.morse_encode(text)

    def morse_decode(self, text: str) -> str:
        return SpecialEncoding.morse_decode(text)

    def tapcode_encode(self, text: str) -> str:
        return SpecialEncoding.tapcode_encode(text)

    def tapcode_decode(self, text: str) -> str:
        return SpecialEncoding.tapcode_decode(text)

    def pigpen_encode(self, text: str) -> str:
        return SpecialEncoding.pigpen_encode(text)

    def pigpen_decode(self, text: str) -> str:
        return SpecialEncoding.pigpen_decode(text)

    def baconian_encode(self, text: str) -> str:
        return SpecialEncoding.baconian_encode(text)

    def baconian_decode(self, text: str) -> str:
        return SpecialEncoding.baconian_decode(text)

    def xxencode_encode(self, text: str) -> str:
        return MiscEncoding.xxencode_encode(text)

    def xxencode_decode(self, text: str) -> str:
        return MiscEncoding.xxencode_decode(text)

    def uuencode_encode(self, text: str) -> str:
        return MiscEncoding.uuencode_encode(text)

    def uuencode_decode(self, text: str) -> str:
        return MiscEncoding.uuencode_decode(text)

    def jsfuck_encode(self, text: str) -> str:
        return MiscEncoding.jsfuck_encode(text)

    def jsfuck_decode(self, text: str) -> str:
        return MiscEncoding.jsfuck_decode(text)

    def brainfuck_encode(self, text: str) -> str:
        return MiscEncoding.brainfuck_encode(text)

    def brainfuck_decode(self, text: str) -> str:
        return MiscEncoding.brainfuck_decode(text)

    def bubble_encode(self, text: str) -> str:
        return MiscEncoding.bubble_encode(text)

    def bubble_decode(self, text: str) -> str:
        return MiscEncoding.bubble_decode(text)

    def aaencode_encode(self, text: str) -> str:
        return MiscEncoding.aaencode_encode(text)

    def aaencode_decode(self, text: str) -> str:
        return MiscEncoding.aaencode_decode(text)

    def jjencode_encode(self, text: str) -> str:
        return MiscEncoding.jjencode_encode(text)

    def jjencode_decode(self, text: str) -> str:
        return MiscEncoding.jjencode_decode(text)

    def ppencode_encode(self, text: str) -> str:
        return MiscEncoding.ppencode_encode(text)

    def ppencode_decode(self, text: str) -> str:
        return MiscEncoding.ppencode_decode(text)

    def md5_hash(self, text: str) -> str:
        return HashFunctions.md5(text)

    def sha1_hash(self, text: str) -> str:
        return HashFunctions.sha1(text)

    def sha256_hash(self, text: str) -> str:
        return HashFunctions.sha256(text)

    def sha384_hash(self, text: str) -> str:
        return HashFunctions.sha384(text)

    def sha512_hash(self, text: str) -> str:
        return HashFunctions.sha512(text)

    def ripemd_hash(self, text: str) -> str:
        return HashFunctions.ripemd160(text)

    def ripemd160_hash(self, text: str) -> str:
        return HashFunctions.ripemd160(text)

    def binary_encode(self, text: str) -> str:
        return BaseConversion.text_to_binary(text)

    def binary_decode(self, text: str) -> str:
        return BaseConversion.binary_to_text(text)

    def octal_encode(self, text: str) -> str:
        return BaseConversion.text_to_octal(text)

    def octal_decode(self, text: str) -> str:
        return BaseConversion.octal_to_text(text)

    def decimal_encode(self, text: str) -> str:
        return BaseConversion.text_to_decimal(text)

    def decimal_decode(self, text: str) -> str:
        return BaseConversion.decimal_to_text(text)

    def hexadecimal_encode(self, text: str) -> str:
        return BaseConversion.text_to_hexadecimal(text)

    def hexadecimal_decode(self, text: str) -> str:
        return BaseConversion.hexadecimal_to_text(text)
