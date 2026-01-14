#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import html
from urllib.parse import quote, unquote


class EncodingConversion:
    @staticmethod
    def hex_encode(text: str) -> str:
        return binascii.hexlify(text.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def hex_decode(text: str) -> str:
        return binascii.unhexlify(text).decode('utf-8')
    
    @staticmethod
    def url_encode(text: str) -> str:
        return quote(text, safe='')
    
    @staticmethod
    def url_decode(text: str) -> str:
        return unquote(text)
    
    @staticmethod
    def html_encode(text: str) -> str:
        return html.escape(text)
    
    @staticmethod
    def html_decode(text: str) -> str:
        return html.unescape(text)
    
    @staticmethod
    def escape_encode(text: str) -> str:
        result = []
        for char in text:
            code = ord(char)
            if code < 32 or code > 126:
                result.append(f'\\x{code:02x}')
            elif char == '\\':
                result.append('\\\\')
            elif char == '"':
                result.append('\\"')
            elif char == "'":
                result.append("\\'")
            elif char == '\n':
                result.append('\\n')
            elif char == '\r':
                result.append('\\r')
            elif char == '\t':
                result.append('\\t')
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def escape_decode(text: str) -> str:
        result = []
        i = 0
        while i < len(text):
            if text[i] == '\\' and i + 1 < len(text):
                next_char = text[i + 1]
                if next_char == 'x' and i + 3 < len(text):
                    result.append(chr(int(text[i+2:i+4], 16)))
                    i += 4
                elif next_char == 'n':
                    result.append('\n')
                    i += 2
                elif next_char == 'r':
                    result.append('\r')
                    i += 2
                elif next_char == 't':
                    result.append('\t')
                    i += 2
                elif next_char == '\\':
                    result.append('\\')
                    i += 2
                elif next_char == '"':
                    result.append('"')
                    i += 2
                elif next_char == "'":
                    result.append("'")
                    i += 2
                else:
                    result.append(text[i])
                    i += 1
            else:
                result.append(text[i])
                i += 1
        return ''.join(result)
    
    @staticmethod
    def ascii_encode(text: str) -> str:
        return ' '.join(str(ord(c)) for c in text)
    
    @staticmethod
    def ascii_decode(text: str) -> str:
        numbers = [int(x) for x in text.split() if x.strip()]
        return ''.join(chr(num) for num in numbers)
    
    @staticmethod
    def quoted_encode(text: str) -> str:
        result = []
        for byte in text.encode('utf-8'):
            if byte >= 33 and byte <= 126 and byte != 61:
                result.append(chr(byte))
            else:
                result.append(f'={byte:02X}')
        return ''.join(result)
    
    @staticmethod
    def quoted_decode(text: str) -> str:
        result = []
        i = 0
        while i < len(text):
            if text[i] == '=' and i + 2 < len(text):
                try:
                    result.append(int(text[i+1:i+3], 16))
                    i += 3
                except:
                    result.append(ord(text[i]))
                    i += 1
            else:
                result.append(ord(text[i]))
                i += 1
        return bytes(result).decode('utf-8', errors='ignore')
