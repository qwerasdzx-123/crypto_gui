#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Dict, List


class SpecialEncoding:
    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..',
        '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
        '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
        ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
        '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
    }
    
    REVERSE_MORSE = {v: k for k, v in MORSE_CODE.items()}
    
    @staticmethod
    def morse_encode(text: str) -> str:
        text = text.upper()
        result = []
        for char in text:
            if char == ' ':
                result.append('/')
            elif char in SpecialEncoding.MORSE_CODE:
                result.append(SpecialEncoding.MORSE_CODE[char])
        return ' '.join(result)
    
    @staticmethod
    def morse_decode(text: str) -> str:
        result = []
        for token in text.split('/'):
            for morse in token.strip().split():
                if morse in SpecialEncoding.REVERSE_MORSE:
                    result.append(SpecialEncoding.REVERSE_MORSE[morse])
            result.append(' ')
        return ''.join(result).strip()
    
    @staticmethod
    def tapcode_encode(text: str) -> str:
        text = text.upper().replace('J', 'I')
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        
        result = []
        for char in text:
            if char == ' ':
                result.append('  ')
            elif char in alphabet:
                idx = alphabet.index(char)
                row = idx // 5 + 1
                col = idx % 5 + 1
                result.append('.' * row + ' ' + '.' * col)
        
        return '  '.join(result)
    
    @staticmethod
    def tapcode_decode(text: str) -> str:
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        
        result = []
        tokens = re.findall(r'\.+(?:\s+\.+)?', text)
        
        for i in range(0, len(tokens), 2):
            if i + 1 < len(tokens):
                row = len(tokens[i].replace(' ', ''))
                col = len(tokens[i+1].replace(' ', ''))
                idx = (row - 1) * 5 + (col - 1)
                if idx < len(alphabet):
                    result.append(alphabet[idx])
        
        return ''.join(result)
    
    @staticmethod
    def _create_pigpen_key() -> Dict[str, str]:
        return {
            'A': '⌇', 'B': '⌇|', 'C': '⌇_', 'D': '⌇|_', 'E': '⌇_',
            'F': '⌇', 'G': '⌇|', 'H': '⌇_', 'I': '⌇|_', 'J': '⌇_',
            'K': '⌇', 'L': '⌇|', 'M': '⌇_', 'N': '⌇|_', 'O': '⌇_',
            'P': '⌇', 'Q': '⌇|', 'R': '⌇_', 'S': '⌇|_', 'T': '⌇_',
            'U': '⌇', 'V': '⌇|', 'W': '⌇_', 'X': '⌇|_', 'Y': '⌇_', 'Z': '⌇_'
        }
    
    @staticmethod
    def pigpen_encode(text: str) -> str:
        pigpen_key = SpecialEncoding._create_pigpen_key()
        return ''.join(pigpen_key.get(char.upper(), char) for char in text)
    
    @staticmethod
    def pigpen_decode(text: str) -> str:
        pigpen_key = SpecialEncoding._create_pigpen_key()
        reverse_key = {v: k for k, v in pigpen_key.items()}
        return ''.join(reverse_key.get(char, char) for char in text)
    
    @staticmethod
    def baconian_encode(text: str) -> str:
        text = text.upper().replace('J', 'I').replace(' ', '')
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        
        result = []
        for char in text:
            if char in alphabet:
                idx = alphabet.index(char)
                binary = format(idx, '05b')
                bacon = binary.replace('0', 'A').replace('1', 'B')
                result.append(bacon)
        
        return ' '.join(result)
    
    @staticmethod
    def baconian_decode(text: str) -> str:
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        text = text.upper().replace(' ', '')
        
        result = []
        for i in range(0, len(text), 5):
            if i + 5 <= len(text):
                bacon = text[i:i+5]
                binary = bacon.replace('A', '0').replace('B', '1')
                try:
                    idx = int(binary, 2)
                    if idx < len(alphabet):
                        result.append(alphabet[idx])
                except:
                    pass
        
        return ''.join(result)
