#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import string
import re
from typing import List, Tuple


class ClassicalCiphers:
    porta_tables = [
        'NOPQRSTUVWXYZABCDEFGHIJKLM',
        'OPQRSTUVWXYZNMABCDEFGHIJKL',
        'PQRSTUVWXYZNOLMABCDEFGHIJK',
        'QRSTUVWXYZNOKLMABCDEFGHIJ',
        'RSTUVWXYZNOKJLMABCDEFGHI',
        'STUVWXYZNOIJKLMABCDEFGH',
        'TUVWXYZNOHIJKLMABCDEFG',
        'UVWXYZNOGHIJKLMABCDEF',
        'VWXYZNOFGHIJKLMABCDE',
        'WXYZNOEFGHIJKLMABCD',
        'XYZNODEFGHIJKLMABC',
        'YZNOCDEFGHIJKLMAB',
        'ZNBCDEFGHIJKLMA',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ]

    @staticmethod
    def _shift_char(char: str, shift: int) -> str:
        if char.isupper():
            return chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        elif char.islower():
            return chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        return char

    @staticmethod
    def _shift_with_key(text: str, key: str, encrypt: bool = True) -> str:
        key = key.upper()
        result = []
        key_index = 0
        for char in text:
            if char.isupper() or char.islower():
                shift = ord(key[key_index % len(key)]) - ord('A')
                result.append(ClassicalCiphers._shift_char(char, shift if encrypt else -shift))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def caesar_encrypt(text: str, shift: int = 3) -> str:
        return ''.join(ClassicalCiphers._shift_char(char, shift) for char in text)
    
    @staticmethod
    def caesar_decrypt(text: str, shift: int = 3) -> str:
        return ClassicalCiphers.caesar_encrypt(text, -shift)
    
    @staticmethod
    def vigenere_encrypt(text: str, key: str) -> str:
        return ClassicalCiphers._shift_with_key(text, key, True)
    
    @staticmethod
    def vigenere_decrypt(text: str, key: str) -> str:
        return ClassicalCiphers._shift_with_key(text, key, False)
    
    @staticmethod
    def railfence_encrypt(text: str, rails: int = 3) -> str:
        if rails <= 1:
            return text
        
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        
        return ''.join([''.join(rail) for rail in fence])
    
    @staticmethod
    def railfence_decrypt(text: str, rails: int = 3) -> str:
        if rails <= 1:
            return text
        
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(None)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        
        index = 0
        for i in range(rails):
            for j in range(len(fence[i])):
                fence[i][j] = text[index]
                index += 1
        
        result = []
        rail = 0
        direction = 1
        for _ in range(len(text)):
            result.append(fence[rail].pop(0))
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        
        return ''.join(result)
    
    @staticmethod
    def rot13_encrypt(text: str) -> str:
        return ClassicalCiphers.caesar_encrypt(text, 13)
    
    @staticmethod
    def rot13_decrypt(text: str) -> str:
        return ClassicalCiphers.caesar_decrypt(text, 13)
    
    @staticmethod
    def atbash_encrypt(text: str) -> str:
        return ''.join(ClassicalCiphers._shift_char(char, 25 - 2 * (ord(char.upper()) - ord('A'))) if char.isalpha() else char for char in text)
    
    @staticmethod
    def atbash_decrypt(text: str) -> str:
        return ClassicalCiphers.atbash_encrypt(text)
    
    @staticmethod
    def affine_encrypt(text: str, a: int = 5, b: int = 8) -> str:
        if a % 2 == 0 or a == 13:
            raise ValueError("a must be coprime with 26")
        return ''.join(ClassicalCiphers._shift_char(char, a * (ord(char.upper()) - ord('A')) + b) if char.isalpha() else char for char in text)
    
    @staticmethod
    def affine_decrypt(text: str, a: int = 5, b: int = 8) -> str:
        if a % 2 == 0 or a == 13:
            raise ValueError("a must be coprime with 26")
        a_inv = pow(a, -1, 26)
        return ''.join(ClassicalCiphers._shift_char(char, a_inv * ((ord(char.upper()) - ord('A')) - b)) if char.isalpha() else char for char in text)
    
    @staticmethod
    def _create_playfair_matrix(key: str) -> List[List[str]]:
        key = key.upper().replace('J', 'I')
        key = ''.join(dict.fromkeys(key + string.ascii_uppercase.replace('J', '')))
        
        matrix = []
        for i in range(5):
            matrix.append(list(key[i*5:(i+1)*5]))
        
        return matrix
    
    @staticmethod
    def _playfair_find_position(matrix: List[List[str]], char: str) -> Tuple[int, int]:
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return (i, j)
        return (-1, -1)
    
    @staticmethod
    def playfair_encrypt(text: str, key: str) -> str:
        matrix = ClassicalCiphers._create_playfair_matrix(key)
        
        text = text.upper().replace('J', 'I').replace(' ', '')
        if len(text) % 2 == 1:
            text += 'X'
        
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            row_a, col_a = ClassicalCiphers._playfair_find_position(matrix, a)
            row_b, col_b = ClassicalCiphers._playfair_find_position(matrix, b)
            
            if row_a == row_b:
                result.append(matrix[row_a][(col_a + 1) % 5])
                result.append(matrix[row_b][(col_b + 1) % 5])
            elif col_a == col_b:
                result.append(matrix[(row_a + 1) % 5][col_a])
                result.append(matrix[(row_b + 1) % 5][col_b])
            else:
                result.append(matrix[row_a][col_b])
                result.append(matrix[row_b][col_a])
        
        return ''.join(result)
    
    @staticmethod
    def playfair_decrypt(text: str, key: str) -> str:
        matrix = ClassicalCiphers._create_playfair_matrix(key)
        
        text = text.upper().replace('J', 'I').replace(' ', '')
        
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            row_a, col_a = ClassicalCiphers._playfair_find_position(matrix, a)
            row_b, col_b = ClassicalCiphers._playfair_find_position(matrix, b)
            
            if row_a == row_b:
                result.append(matrix[row_a][(col_a - 1) % 5])
                result.append(matrix[row_b][(col_b - 1) % 5])
            elif col_a == col_b:
                result.append(matrix[(row_a - 1) % 5][col_a])
                result.append(matrix[(row_b - 1) % 5][col_b])
            else:
                result.append(matrix[row_a][col_b])
                result.append(matrix[row_b][col_a])
        
        return ''.join(result)
    
    @staticmethod
    def beaufort_encrypt(text: str, key: str) -> str:
        return ClassicalCiphers._shift_with_key(text, key, False)
    
    @staticmethod
    def beaufort_decrypt(text: str, key: str) -> str:
        return ClassicalCiphers.beaufort_encrypt(text, key)
    
    @staticmethod
    def porta_encrypt(text: str, key: str) -> str:
        key = key.upper()
        result = []
        key_index = 0
        
        for char in text:
            if char.isupper():
                key_char = key[key_index % len(key)]
                table_index = (ord(key_char) - ord('A')) // 2
                result.append(ClassicalCiphers.porta_tables[table_index][ord(char) - ord('A')])
                key_index += 1
            elif char.islower():
                key_char = key[key_index % len(key)]
                table_index = (ord(key_char) - ord('A')) // 2
                result.append(ClassicalCiphers.porta_tables[table_index][ord(char) - ord('a')].lower())
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def porta_decrypt(text: str, key: str) -> str:
        key = key.upper()
        result = []
        key_index = 0
        
        for char in text:
            if char.isupper():
                key_char = key[key_index % len(key)]
                table_index = (ord(key_char) - ord('A')) // 2
                result.append(chr(ClassicalCiphers.porta_tables[table_index].index(char.upper()) + ord('A')))
                key_index += 1
            elif char.islower():
                key_char = key[key_index % len(key)]
                table_index = (ord(key_char) - ord('A')) // 2
                result.append(chr(ClassicalCiphers.porta_tables[table_index].index(char.upper()) + ord('a')))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def autokey_encrypt(text: str, key: str) -> str:
        key = key.upper()
        full_key = key + text.upper()
        return ''.join(ClassicalCiphers._shift_char(char, ord(full_key[i]) - ord('A')) if char.isalpha() else char for i, char in enumerate(text))
    
    @staticmethod
    def autokey_decrypt(text: str, key: str) -> str:
        key = key.upper()
        result = []
        for i, char in enumerate(text):
            if char.isupper():
                shift = ord(key[i % len(key)]) - ord('A')
                decrypted = ClassicalCiphers._shift_char(char, -shift)
                result.append(decrypted)
                key += decrypted
            elif char.islower():
                shift = ord(key[i % len(key)]) - ord('A')
                decrypted = ClassicalCiphers._shift_char(char, -shift)
                result.append(decrypted)
                key += decrypted.upper()
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def bifid_encrypt(text: str, key: str) -> str:
        key = key.upper().replace('J', 'I')
        key = ''.join(dict.fromkeys(key + string.ascii_uppercase.replace('J', '')))
        
        row = []
        col = []
        for char in text.upper().replace('J', 'I'):
            if char in key:
                idx = key.index(char)
                row.append(idx // 5)
                col.append(idx % 5)
        
        combined = row + col
        result = []
        for i in range(0, len(combined), 2):
            if i + 1 < len(combined):
                result.append(key[combined[i] * 5 + combined[i+1]])
        
        return ''.join(result)
    
    @staticmethod
    def bifid_decrypt(text: str, key: str) -> str:
        key = key.upper().replace('J', 'I')
        key = ''.join(dict.fromkeys(key + string.ascii_uppercase.replace('J', '')))
        
        row_col = []
        for char in text.upper().replace('J', 'I'):
            if char in key:
                idx = key.index(char)
                row_col.append(idx // 5)
                row_col.append(idx % 5)
        
        mid = len(row_col) // 2
        row = row_col[:mid]
        col = row_col[mid:]
        
        result = []
        for i in range(len(row)):
            result.append(key[row[i] * 5 + col[i]])
        
        return ''.join(result)
    
    @staticmethod
    def _create_four_square_matrix(key1: str, key2: str) -> Tuple[List[List[str]], List[List[str]]]:
        key1 = key1.upper().replace('J', 'I')
        key2 = key2.upper().replace('J', 'I')
        
        alphabet = string.ascii_uppercase.replace('J', '')
        matrix1 = []
        matrix2 = []
        
        key1 = ''.join(dict.fromkeys(key1 + alphabet))
        key2 = ''.join(dict.fromkeys(key2 + alphabet))
        
        for i in range(5):
            matrix1.append(list(key1[i*5:(i+1)*5]))
            matrix2.append(list(key2[i*5:(i+1)*5]))
        
        return (matrix1, matrix2)
    
    @staticmethod
    def four_encrypt(text: str, key: str) -> str:
        key1, key2 = key.split('|') if '|' in key else (key, key)
        matrix1, matrix2 = ClassicalCiphers._create_four_square_matrix(key1, key2)
        
        text = text.upper().replace('J', 'I').replace(' ', '')
        if len(text) % 2 == 1:
            text += 'X'
        
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            
            pos_a = ClassicalCiphers._playfair_find_position(matrix1, a)
            pos_b = ClassicalCiphers._playfair_find_position(matrix2, b)
            
            result.append(matrix1[pos_a[0]][pos_b[1]])
            result.append(matrix2[pos_b[0]][pos_a[1]])
        
        return ''.join(result)
    
    @staticmethod
    def four_decrypt(text: str, key: str) -> str:
        key1, key2 = key.split('|') if '|' in key else (key, key)
        matrix1, matrix2 = ClassicalCiphers._create_four_square_matrix(key1, key2)
        
        text = text.upper().replace('J', 'I').replace(' ', '')
        
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            
            pos_a = ClassicalCiphers._playfair_find_position(matrix1, a)
            pos_b = ClassicalCiphers._playfair_find_position(matrix2, b)
            
            result.append(matrix1[pos_a[0]][pos_b[1]])
            result.append(matrix2[pos_b[0]][pos_a[1]])
        
        return ''.join(result)
    
    @staticmethod
    def gronsfeld_encrypt(text: str, key: str) -> str:
        result = []
        key_index = 0
        for char in text:
            if char.isupper():
                shift = int(key[key_index % len(key)])
                result.append(ClassicalCiphers._shift_char(char, shift))
                key_index += 1
            elif char.islower():
                shift = int(key[key_index % len(key)])
                result.append(ClassicalCiphers._shift_char(char, shift))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def gronsfeld_decrypt(text: str, key: str) -> str:
        result = []
        key_index = 0
        for char in text:
            if char.isupper():
                shift = int(key[key_index % len(key)])
                result.append(ClassicalCiphers._shift_char(char, -shift))
                key_index += 1
            elif char.islower():
                shift = int(key[key_index % len(key)])
                result.append(ClassicalCiphers._shift_char(char, -shift))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def keyword_encrypt(text: str, key: str) -> str:
        key = key.upper()
        alphabet = string.ascii_uppercase
        key_alphabet = ''.join(dict.fromkeys(key + alphabet))
        return ''.join(key_alphabet[alphabet.index(char.upper())].lower() if char.islower() else key_alphabet[alphabet.index(char)] if char.isupper() else char for char in text)
    
    @staticmethod
    def keyword_decrypt(text: str, key: str) -> str:
        key = key.upper()
        alphabet = string.ascii_uppercase
        key_alphabet = ''.join(dict.fromkeys(key + alphabet))
        return ''.join(alphabet[key_alphabet.index(char.upper())].lower() if char.islower() else alphabet[key_alphabet.index(char)] if char.isupper() else char for char in text)
    
    runkey_encrypt = vigenere_encrypt
    runkey_decrypt = vigenere_decrypt
    simple_encrypt = keyword_encrypt
    simple_decrypt = keyword_decrypt
    
    @staticmethod
    def columnar_encrypt(text: str, key: str) -> str:
        return ClassicalCiphers._columnar_transposition_encrypt(text.upper().replace(' ', ''), key.upper())
    
    @staticmethod
    def columnar_decrypt(text: str, key: str) -> str:
        return ClassicalCiphers._columnar_transposition_decrypt(text, key.upper())
    
    @staticmethod
    def a1z26_encrypt(text: str) -> str:
        return ' '.join(str(ord(char.upper()) - ord('A') + 1) if char.isalpha() else char for char in text)
    
    @staticmethod
    def a1z26_decrypt(text: str) -> str:
        return ''.join(chr(int(token) + ord('A') - 1) if token.isdigit() else token for token in text.split())
    
    @staticmethod
    def _create_adfgx_matrix(key: str) -> List[List[str]]:
        key = key.upper().replace('J', 'I')
        alphabet = string.ascii_uppercase.replace('J', '')
        key_alphabet = ''.join(dict.fromkeys(key + alphabet))
        return [list(key_alphabet[i*5:(i+1)*5]) for i in range(5)]
    
    @staticmethod
    def _columnar_transposition_encrypt(text: str, key: str) -> str:
        num_cols = len(key)
        num_rows = (len(text) + num_cols - 1) // num_cols
        grid = [list(text[i*num_cols:(i+1)*num_cols]) + ['X'] * (num_cols - len(text[i*num_cols:(i+1)*num_cols])) for i in range(num_rows)]
        key_order = sorted([(char, i) for i, char in enumerate(key)])
        return ''.join(row[col_idx] for char, col_idx in key_order for row in grid)
    
    @staticmethod
    def _columnar_transposition_decrypt(text: str, key: str) -> str:
        num_cols = len(key)
        num_rows = (len(text) + num_cols - 1) // num_cols
        key_order = sorted([(char, i) for i, char in enumerate(key)])
        col_lengths = [num_rows + 1 if i < len(text) % num_cols else num_rows for i in range(num_cols)]
        cols = {col_idx: list(text[idx:idx+col_lengths[col_idx]]) for idx, (char, col_idx) in enumerate(key_order)}
        grid = [[cols[col_idx][row_idx] if row_idx < len(cols[col_idx]) else '' for col_idx in range(num_cols)] for row_idx in range(num_rows)]
        return ''.join(char for row in grid for char in row if char and char != 'X')
    
    @staticmethod
    def adfgx_encrypt(text: str, key: str) -> str:
        matrix = ClassicalCiphers._create_adfgx_matrix(key)
        rows = 'ADFGX'
        text = text.upper().replace('J', 'I').replace(' ', '')
        intermediate = ''.join(rows[i] + rows[j] for char in text for i in range(5) for j in range(5) if matrix[i][j] == char)
        return ClassicalCiphers._columnar_transposition_encrypt(intermediate, key)
    
    @staticmethod
    def adfgx_decrypt(text: str, key: str) -> str:
        matrix = ClassicalCiphers._create_adfgx_matrix(key)
        rows = 'ADFGX'
        intermediate = ClassicalCiphers._columnar_transposition_decrypt(text, key)
        return ''.join(matrix[rows.index(intermediate[i])][rows.index(intermediate[i+1])] for i in range(0, len(intermediate), 2))
    
    @staticmethod
    def _create_adfgvx_matrix(key: str) -> List[List[str]]:
        key = key.upper()
        alphabet = string.ascii_uppercase + string.digits
        key_alphabet = ''.join(dict.fromkeys(key + alphabet))
        return [list(key_alphabet[i*6:(i+1)*6]) for i in range(6)]
    
    @staticmethod
    def adfgvx_encrypt(text: str, key: str) -> str:
        matrix = ClassicalCiphers._create_adfgvx_matrix(key)
        rows = 'ADFGVX'
        text = text.upper().replace(' ', '')
        intermediate = ''.join(rows[i] + rows[j] for char in text for i in range(6) for j in range(6) if matrix[i][j] == char)
        return ClassicalCiphers._columnar_transposition_encrypt(intermediate, key)
    
    @staticmethod
    def adfgvx_decrypt(text: str, key: str) -> str:
        matrix = ClassicalCiphers._create_adfgvx_matrix(key)
        rows = 'ADFGVX'
        intermediate = ClassicalCiphers._columnar_transposition_decrypt(text, key)
        return ''.join(matrix[rows.index(intermediate[i])][rows.index(intermediate[i+1])] for i in range(0, len(intermediate), 2))
