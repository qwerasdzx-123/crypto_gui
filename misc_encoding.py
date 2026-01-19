import base64
import re
import subprocess
from typing import Tuple, List


class MiscEncoding:
    XXENCODE_CHARS = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    XXENCODE_PADDING = '+'
    
    UUENCODE_CHARS = '`!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'
    
    BUBBLE_VOWELS = 'aeiouy'
    BUBBLE_CONSONANTS = 'bcdfghklmnprstvzx'
    
    @staticmethod
    def xxencode_encode(text: str) -> str:
        data = text.encode('utf-8')
        result = []
        
        for i in range(0, len(data), 3):
            chunk = data[i:i+3]
            while len(chunk) < 3:
                chunk += b'\x00'
            
            n = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]
            
            result.append(MiscEncoding.XXENCODE_CHARS[(n >> 18) & 0x3F])
            result.append(MiscEncoding.XXENCODE_CHARS[(n >> 12) & 0x3F])
            result.append(MiscEncoding.XXENCODE_CHARS[(n >> 6) & 0x3F])
            result.append(MiscEncoding.XXENCODE_CHARS[n & 0x3F])
        
        return ''.join(result)
    
    @staticmethod
    def xxencode_decode(text: str) -> str:
        result = []
        text = text.strip()
        
        for i in range(0, len(text), 4):
            chunk = text[i:i+4]
            if len(chunk) < 4:
                break
            
            n = 0
            for char in chunk:
                if char in MiscEncoding.XXENCODE_CHARS:
                    n = (n << 6) | MiscEncoding.XXENCODE_CHARS.index(char)
                else:
                    raise ValueError(f"Invalid character in XXencode: {char}")
            
            result.append((n >> 16) & 0xFF)
            result.append((n >> 8) & 0xFF)
            result.append(n & 0xFF)
        
        data = bytes(result)
        return data.rstrip(b'\x00').decode('utf-8')
    
    @staticmethod
    def uuencode_encode(text: str) -> str:
        data = text.encode('utf-8')
        result = []
        
        for i in range(0, len(data), 45):
            chunk = data[i:i+45]
            length_char = chr(len(chunk) + 32)
            encoded = base64.b64encode(chunk).decode('ascii')
            encoded = encoded.replace('+', '`')
            encoded = encoded.replace('/', ',')
            result.append(length_char + encoded)
        
        return '\n'.join(result) + '\n`\n'
    
    @staticmethod
    def uuencode_decode(text: str) -> str:
        lines = text.strip().split('\n')
        result = []
        
        for line in lines:
            if not line or line.startswith('`'):
                continue
            
            length_char = line[0]
            length = ord(length_char) - 32
            
            if length <= 0:
                continue
            
            encoded = line[1:]
            encoded = encoded.replace('`', '+')
            encoded = encoded.replace(',', '/')
            
            try:
                decoded = base64.b64decode(encoded)
                result.append(decoded[:length])
            except:
                continue
        
        return b''.join(result).decode('utf-8')
    
    @staticmethod
    def jsfuck_encode(text: str) -> str:
        jsfuck_map = {
            'a': '(![]+[])[+!+[]]',
            'b': '([]["entries"]()+"")[2]',
            'c': '([]["fill"]+"")[3]',
            'd': '(undefined+"")[2]',
            'e': '(true+"")[3]',
            'f': '(false+"")[0]',
            'g': '(false+[0]+String)[20]',
            'h': '(+(101))["to"+String["name"]](21)[1]',
            'i': '([false]+undefined)[10]',
            'j': '([]["entries"]()+"")[3]',
            'k': '(+(100))["to"+String["name"]](31)[1]',
            'l': '(false+"")[2]',
            'm': '(Number+"")[11]',
            'n': '(undefined+"")[1]',
            'o': '(true+[]["fill"])[10]',
            'p': '(+(211))["to"+String["name"]](31)[1]',
            'q': '([]+String)[21]',
            'r': '(true+"")[1]',
            's': '(false+"")[3]',
            't': '(true+"")[0]',
            'u': '(undefined+"")[0]',
            'v': '(+(31))["to"+String["name"]](32)[1]',
            'w': '(+(32))["to"+String["name"]](33)[1]',
            'x': '(+(101))["to"+String["name"]](34)[1]',
            'y': '(NaN+[11])[0]',
            'z': '(+(35))["to"+String["name"]](36)[1]',
            '0': '(+[![]]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]',
            '1': '[+!+[]]+[]',
            '2': '(+!+[]+[+!+[]])',
            '3': '(+!+[]+[+!+[]]+[+!+[]])',
            '4': '(+!+[]+[+!+[]]+[+!+[]]+[+!+[]])',
            '5': '(+!+[]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]])',
            '6': '(+!+[]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]])',
            '7': '(+!+[]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]])',
            '8': '(+!+[]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]])',
            '9': '(+!+[]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]]+[+!+[]])',
            ' ': '([]+[])[+[]]',
            '!': '(+!+[]+"")',
            '"': '([]+[]["fill"])[+[]]',
            '#': '([]+[]["fill"])[+!+[]]',
            '$': '([]+[]["fill"])[+!+[]+[+!+[]]]',
            '%': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]]]]',
            '&': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]',
            "'": '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]',
            '(': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]',
            ')': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]',
            '*': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]',
            '+': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]',
            ',': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]',
            '-': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]',
            '.': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]',
            '/': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]',
            ':': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]',
            ';': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]',
            '<': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]',
            '=': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]',
            '>': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]',
            '?': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]',
            '@': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]',
            '[': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]',
            '\\': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]',
            ']': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]',
            '^': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]',
            '_': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]]',
            '`': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]]',
            '{': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]]]]',
            '|': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]',
            '}': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]',
            '~': '([]+[]["fill"])[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]+[+!+[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]'
        }
        
        result = []
        for char in text:
            if char in jsfuck_map:
                result.append(jsfuck_map[char])
            else:
                result.append(f'"{char}"')
        
        return '+'.join(result)
    
    @staticmethod
    def jsfuck_decode(code: str) -> str:
        try:
            js_code = f'console.log(String({code}));'
            result = subprocess.run(['node', '-e', js_code], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                raise RuntimeError(f"JSFuck解码失败: {result.stderr}")
        except FileNotFoundError:
            raise RuntimeError("JSFuck解码需要Node.js环境，请确保已安装Node.js")
        except subprocess.TimeoutExpired:
            raise RuntimeError("JSFuck解码超时，代码可能过于复杂")
        except Exception as e:
            raise RuntimeError(f"JSFuck解码错误: {str(e)}")
    
    @staticmethod
    def brainfuck_encode(text: str) -> str:
        result = []
        current = 0
        
        for char in text:
            target = ord(char)
            diff = target - current
            
            if diff > 0:
                result.append('+' * diff)
            elif diff < 0:
                result.append('-' * abs(diff))
            
            result.append('.')
            current = target
        
        return ''.join(result)
    
    @staticmethod
    def brainfuck_decode(code: str) -> str:
        cells = [0] * 30000
        pointer = 0
        result = []
        i = 0
        loop_stack = []
        
        loop_map = {}
        for j, char in enumerate(code):
            if char == '[':
                loop_stack.append(j)
            elif char == ']':
                if loop_stack:
                    start = loop_stack.pop()
                    loop_map[start] = j
                    loop_map[j] = start
        
        while i < len(code):
            char = code[i]
            
            if char == '>':
                pointer += 1
            elif char == '<':
                pointer -= 1
            elif char == '+':
                cells[pointer] = (cells[pointer] + 1) % 256
            elif char == '-':
                cells[pointer] = (cells[pointer] - 1) % 256
            elif char == '.':
                result.append(chr(cells[pointer]))
            elif char == ',':
                pass
            elif char == '[':
                if cells[pointer] == 0:
                    i = loop_map[i]
            elif char == ']':
                if cells[pointer] != 0:
                    i = loop_map[i]
            
            i += 1
        
        return ''.join(result)
    
    @staticmethod
    def bubble_encode(text: str) -> str:
        vowels = 'aeiouy'
        consonants = 'bcdfghklmnprstvzx'
        
        data = text.encode('utf-8')
        
        out = 'x'
        c = 1
        
        for i in range(0, len(data) + 1, 2):
            if i >= len(data):
                out += vowels[c % 6] + consonants[16] + vowels[c // 6]
                break
            
            byte1 = data[i]
            out += vowels[(((byte1 >> 6) & 3) + c) % 6]
            out += consonants[(byte1 >> 2) & 15]
            out += vowels[((byte1 & 3) + (c // 6)) % 6]
            
            if (i + 1) >= len(data):
                break
            
            byte2 = data[i + 1]
            out += consonants[(byte2 >> 4) & 15]
            out += '-'
            out += consonants[byte2 & 15]
            c = (c * 5 + byte1 * 7 + byte2) % 36
        
        out += 'x'
        return out
    
    @staticmethod
    def bubble_decode(code: str) -> str:
        vowels = 'aeiouy'
        consonants = 'bcdfghklmnprstvzx'
        
        c = 1
        
        if len(code) < 2 or code[0] != 'x':
            raise ValueError("corrupt string at offset 0: must begin with a 'x'")
        
        if code[-1] != 'x':
            raise ValueError("corrupt string at last offset: must end with a 'x'")
        
        if len(code) != 5 and len(code) % 6 != 5:
            raise ValueError("corrupt string: wrong length")
        
        src = code[1:-1]
        src = list(enumerate([src[x:x+6] for x in range(0, len(src), 6)]))
        last_tuple = len(src) - 1
        out = bytearray()
        
        for k, tup in src:
            pos = k * 6
            
            try:
                decoded = [vowels.index(tup[0]), consonants.index(tup[1]), vowels.index(tup[2])]
                try:
                    decoded.append(consonants.index(tup[3]))
                    decoded.append('-')
                    decoded.append(consonants.index(tup[5]))
                except:
                    pass
            except ValueError as e:
                raise ValueError(f"corrupt string at offset {pos}: invalid character")
            
            if k == last_tuple:
                if decoded[1] == 16:
                    if decoded[0] != c % 6:
                        raise ValueError(f"corrupt string at offset {pos} (checksum)")
                    if decoded[2] != c // 6:
                        raise ValueError(f"corrupt string at offset {pos+2} (checksum)")
                else:
                    byte = MiscEncoding._decode_3way_byte(decoded[0], decoded[1], decoded[2], pos, c)
                    out.append(byte)
            else:
                byte1 = MiscEncoding._decode_3way_byte(decoded[0], decoded[1], decoded[2], pos, c)
                byte2 = MiscEncoding._decode_2way_byte(decoded[3], decoded[5], pos)
                out.append(byte1)
                out.append(byte2)
                c = (c * 5 + byte1 * 7 + byte2) % 36
        
        return out.decode('utf-8')
    
    @staticmethod
    def _decode_2way_byte(a1, a2, offset):
        if a1 > 16:
            raise ValueError(f"corrupt string at offset {offset}")
        if a2 > 16:
            raise ValueError(f"corrupt string at offset {offset+2}")
        return (a1 << 4) | a2
    
    @staticmethod
    def _decode_3way_byte(a1, a2, a3, offset, c):
        high2 = (a1 - (c % 6) + 6) % 6
        if high2 >= 4:
            raise ValueError(f"corrupt string at offset {offset}")
        if a2 > 16:
            raise ValueError(f"corrupt string at offset {offset+1}")
        mid4 = a2
        low2 = (a3 - (c // 6 % 6) + 6) % 6
        if low2 >= 4:
            raise ValueError(f"corrupt string at offset {offset+2}")
        return (high2 << 6) | (mid4 << 2) | low2
    
    @staticmethod
    def aaencode_encode(text: str) -> str:
        aaencode_map = {
            'A': 'ﾟωﾟﾉ',
            'F': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'G': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'H': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'I': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'J': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'K': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'L': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'M': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'N': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'O': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'P': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'Q': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'R': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'S': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'T': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'U': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'V': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'W': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'X': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'Y': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'Z': '(ﾟДﾟ)≡ﾟΘﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ≡ﾟДﾟ)',
            'a': '(ﾟΘﾟ)',
            'b': '(oﾟｰﾟ)',
            'c': '(cﾟｰﾟ)',
            'd': '(ﾟДﾟ)[ﾟoﾟ]',
            'e': '(ﾟДﾟ)[ﾟεﾟ]',
            'f': '(ﾟΘﾟ)',
            'g': '(ﾟДﾟ)[ﾟΘﾟ]',
            'h': '(cﾟoﾟ)',
            'i': '(oﾟｰﾟo)',
            'j': '(ﾟДﾟ)[ﾟcﾟ]',
            'k': '(ﾟΘﾟ)',
            'l': '(lﾟｰﾟ)',
            'm': '(oﾟｰﾟo)',
            'n': '(ﾟДﾟ)[ﾟhﾟ]',
            'o': '(cﾟｰﾟ)',
            'p': '(ﾟДﾟ)[ﾟoﾟ]',
            'q': '(oﾟｰﾟo)',
            'r': '(ﾟДﾟ)[ﾟεﾟ]',
            's': '(sﾟｰﾟ)',
            't': '(ﾟΘﾟ)',
            'u': '(uﾟｰﾟ)',
            'v': '(ﾟДﾟ)[ﾟεﾟ]',
            'w': '(wﾟｰﾟ)',
            'x': '(xﾟｰﾟ)',
            'y': '(ﾟДﾟ)[ﾟεﾟ]',
            'z': '(zﾟｰﾟ)',
            '0': '(oﾟｰﾟo)',
            '1': '(ﾟΘﾟ)',
            '2': '(ﾟДﾟ)[ﾟoﾟ]',
            '3': '(ﾟДﾟ)[ﾟεﾟ]',
            '4': '(cﾟｰﾟ)',
            '5': '(ﾟДﾟ)[ﾟΘﾟ]',
            '6': '(cﾟoﾟ)',
            '7': '(oﾟｰﾟo)',
            '8': '(ﾟДﾟ)[ﾟcﾟ]',
            '9': '(lﾟｰﾟ)',
            ' ': '(ﾟДﾟ)[ﾟωﾟﾉ]',
            '!': '(ﾟΘﾟﾉ)',
            '"': '(ﾟДﾟ)[ﾟΘﾟﾉ]',
            '#': '(ﾟДﾟ)[ﾟεﾟﾉ]',
            '$': '(ﾟДﾟ)[ﾟcﾟﾉ]',
            '%': '(ﾟДﾟ)[ﾟhﾟﾉ]',
            '&': '(ﾟДﾟ)[ﾟoﾟﾉ]',
            "'": '(ﾟДﾟ)[ﾟωﾟﾉ]',
            '(': '(ﾟДﾟ)[ﾟΘﾟﾉ]',
            ')': '(ﾟДﾟ)[ﾟεﾟﾉ]',
            '*': '(ﾟДﾟ)[ﾟcﾟﾉ]',
            '+': '(ﾟДﾟ)[ﾟhﾟﾉ]',
            ',': '(ﾟДﾟ)[ﾟoﾟﾉ]',
            '-': '(ﾟДﾟ)[ﾟωﾟﾉ]',
            '.': '(ﾟДﾟ)[ﾟΘﾟﾉ]',
            '/': '(ﾟДﾟ)[ﾟεﾟﾉ]',
            ':': '(ﾟДﾟ)[ﾟcﾟﾉ]',
            ';': '(ﾟДﾟ)[ﾟhﾟﾉ]',
            '<': '(ﾟДﾟ)[ﾟoﾟﾉ]',
            '=': '(ﾟДﾟ)[ﾟωﾟﾉ]',
            '>': '(ﾟДﾟ)[ﾟΘﾟﾉ]',
            '?': '(ﾟДﾟ)[ﾟεﾟﾉ]',
            '@': '(ﾟДﾟ)[ﾟcﾟﾉ]',
            '[': '(ﾟДﾟ)[ﾟhﾟﾉ]',
            '\\': '(ﾟДﾟ)[ﾟoﾟﾉ]',
            ']': '(ﾟДﾟ)[ﾟωﾟﾉ]',
            '^': '(ﾟДﾟ)[ﾟΘﾟﾉ]',
            '_': '(ﾟДﾟ)[ﾟεﾟﾉ]',
            '`': '(ﾟДﾟ)[ﾟcﾟﾉ]',
            '{': '(ﾟДﾟ)[ﾟhﾟﾉ]',
            '|': '(ﾟДﾟ)[ﾟoﾟﾉ]',
            '}': '(ﾟДﾟ)[ﾟωﾟﾉ]',
            '~': '(ﾟДﾟ)[ﾟΘﾟﾉ]'
        }
        
        result = []
        for char in text:
            if char in aaencode_map:
                result.append(aaencode_map[char])
            else:
                result.append(f'"{char}"')
        
        return ''.join(result)
    
    @staticmethod
    def aaencode_encode(text: str) -> str:
        aaencode_map = {
            'A': 'ﾟωﾟﾉ',
            'B': 'ﾟΘﾟ',
            'C': 'ﾟДﾟ',
            'D': 'ﾟΘﾟﾉ',
            'E': 'ﾟДﾟﾉ',
            'F': 'ﾟΘﾟ',
            'G': 'ﾟДﾟ',
            'H': 'ﾟΘﾟﾉ',
            'I': 'ﾟДﾟﾉ',
            'J': 'ﾟΘﾟ',
            'K': 'ﾟДﾟ',
            'L': 'ﾟΘﾟﾉ',
            'M': 'ﾟДﾟﾉ',
            'N': 'ﾟΘﾟ',
            'O': 'ﾟДﾟ',
            'P': 'ﾟΘﾟﾉ',
            'Q': 'ﾟДﾟﾉ',
            'R': 'ﾟΘﾟ',
            'S': 'ﾟДﾟ',
            'T': 'ﾟΘﾟﾉ',
            'U': 'ﾟДﾟﾉ',
            'V': 'ﾟΘﾟ',
            'W': 'ﾟДﾟ',
            'X': 'ﾟΘﾟﾉ',
            'Y': 'ﾟДﾟﾉ',
            'Z': 'ﾟΘﾟ',
            'a': 'ﾟωﾟﾉ',
            'b': 'ﾟΘﾟ',
            'c': 'ﾟДﾟ',
            'd': 'ﾟΘﾟﾉ',
            'e': 'ﾟДﾟﾉ',
            'f': 'ﾟΘﾟ',
            'g': 'ﾟДﾟ',
            'h': 'ﾟΘﾟﾉ',
            'i': 'ﾟДﾟﾉ',
            'j': 'ﾟΘﾟ',
            'k': 'ﾟДﾟ',
            'l': 'ﾟΘﾟﾉ',
            'm': 'ﾟДﾟﾉ',
            'n': 'ﾟΘﾟ',
            'o': 'ﾟДﾟ',
            'p': 'ﾟΘﾟﾉ',
            'q': 'ﾟДﾟﾉ',
            'r': 'ﾟΘﾟ',
            's': 'ﾟДﾟ',
            't': 'ﾟΘﾟﾉ',
            'u': 'ﾟДﾟﾉ',
            'v': 'ﾟΘﾟ',
            'w': 'ﾟДﾟ',
            'x': 'ﾟΘﾟﾉ',
            'y': 'ﾟДﾟﾉ',
            'z': 'ﾟΘﾟ',
            '0': 'ﾟωﾟﾉ',
            '1': 'ﾟΘﾟ',
            '2': 'ﾟДﾟ',
            '3': 'ﾟΘﾟﾉ',
            '4': 'ﾟДﾟﾉ',
            '5': 'ﾟΘﾟ',
            '6': 'ﾟДﾟ',
            '7': 'ﾟΘﾟﾉ',
            '8': 'ﾟДﾟﾉ',
            '9': 'ﾟΘﾟ',
            ' ': 'ﾟωﾟﾉ',
            '!': 'ﾟΘﾟﾉ',
            '"': 'ﾟДﾟﾉ',
            '#': 'ﾟΘﾟ',
            '$': 'ﾟДﾟ',
            '%': 'ﾟΘﾟﾉ',
            '&': 'ﾟДﾟﾉ',
            "'": 'ﾟΘﾟ',
            '(': 'ﾟДﾟ',
            ')': 'ﾟΘﾟﾉ',
            '*': 'ﾟДﾟﾉ',
            '+': 'ﾟΘﾟ',
            ',': 'ﾟДﾟ',
            '-': 'ﾟΘﾟﾉ',
            '.': 'ﾟДﾟﾉ',
            '/': 'ﾟΘﾟ',
            ':': 'ﾟДﾟ',
            ';': 'ﾟΘﾟﾉ',
            '<': 'ﾟДﾟﾉ',
            '=': 'ﾟΘﾟ',
            '>': 'ﾟДﾟ',
            '?': 'ﾟΘﾟﾉ',
            '@': 'ﾟДﾟﾉ',
            '[': 'ﾟΘﾟ',
            '\\': 'ﾟДﾟ',
            ']': 'ﾟΘﾟﾉ',
            '^': 'ﾟДﾟﾉ',
            '_': 'ﾟΘﾟ',
            '`': 'ﾟДﾟ',
            '{': 'ﾟΘﾟﾉ',
            '|': 'ﾟДﾟﾉ',
            '}': 'ﾟΘﾟ',
            '~': 'ﾟДﾟ'
        }
        
        result = []
        for char in text:
            if char in aaencode_map:
                result.append(aaencode_map[char])
            else:
                result.append(f'"{char}"')
        
        return ''.join(result)
    
    @staticmethod
    def aaencode_decode(code: str) -> str:
        raise NotImplementedError("AAencode decoding is not supported due to its complexity")
    
    @staticmethod
    def jjencode_encode(text: str) -> str:
        jjencode_map = {
            'A': '$',
            'B': '_$',
            'C': '$$',
            'D': '$_',
            'E': '$_$',
            'F': '$$__',
            'G': '$_$',
            'H': '$$_',
            'I': '$$$',
            'J': '$_$_',
            'K': '$__',
            'L': '$_$$',
            'M': '$_$',
            'N': '$__',
            'O': '$$$',
            'P': '$_$_',
            'Q': '$__',
            'R': '$_$$',
            'S': '$_$',
            'T': '$__',
            'U': '$$$',
            'V': '$_$_',
            'W': '$__',
            'X': '$_$$',
            'Y': '$_$',
            'Z': '$__',
            'a': '$',
            'b': '_$',
            'c': '$$',
            'd': '$_',
            'e': '$_$',
            'f': '$$__',
            'g': '$_$',
            'h': '$$_',
            'i': '$$$',
            'j': '$_$_',
            'k': '$__',
            'l': '$_$$',
            'm': '$_$',
            'n': '$__',
            'o': '$$$',
            'p': '$_$_',
            'q': '$__',
            'r': '$_$$',
            's': '$_$',
            't': '$__',
            'u': '$$$',
            'v': '$_$_',
            'w': '$__',
            'x': '$_$$',
            'y': '$_$',
            'z': '$__',
            '0': '$',
            '1': '_$',
            '2': '$$',
            '3': '$_',
            '4': '$_$',
            '5': '$$__',
            '6': '$_$',
            '7': '$$_',
            '8': '$$$',
            '9': '$_$_',
            ' ': '$__',
            '!': '_$',
            '"': '$$',
            '#': '$_',
            '$': '$_$',
            '%': '$$__',
            '&': '$_$',
            "'": '$$_',
            '(': '$$$',
            ')': '$_$_',
            '*': '$__',
            '+': '_$',
            ',': '$$',
            '-': '$_',
            '.': '$_$',
            '/': '$$__',
            ':': '$_$',
            ';': '$$_',
            '<': '$$$',
            '=': '$_$_',
            '>': '$__',
            '?': '_$',
            '@': '$$',
            '[': '$_',
            '\\': '$_$',
            ']': '$$__',
            '^': '$_$',
            '_': '$$_',
            '`': '$$$',
            '{': '$_$_',
            '|': '$__',
            '}': '_$',
            '~': '$$'
        }
        
        result = []
        for char in text:
            if char in jjencode_map:
                result.append(jjencode_map[char])
            else:
                result.append(f'"{char}"')
        
        return ''.join(result)
    
    @staticmethod
    def jjencode_decode(code: str) -> str:
        raise NotImplementedError("JJencode decoding is not supported due to its complexity")
    
    @staticmethod
    def ppencode_encode(text: str) -> str:
        ppencode_map = {
            'A': 'ﾟωﾟﾉ',
            'B': 'ﾟΘﾟ',
            'C': 'ﾟДﾟ',
            'D': 'ﾟΘﾟﾉ',
            'E': 'ﾟДﾟﾉ',
            'F': 'ﾟΘﾟ',
            'G': 'ﾟДﾟ',
            'H': 'ﾟΘﾟﾉ',
            'I': 'ﾟДﾟﾉ',
            'J': 'ﾟΘﾟ',
            'K': 'ﾟДﾟ',
            'L': 'ﾟΘﾟﾉ',
            'M': 'ﾟДﾟﾉ',
            'N': 'ﾟΘﾟ',
            'O': 'ﾟДﾟ',
            'P': 'ﾟΘﾟﾉ',
            'Q': 'ﾟДﾟﾉ',
            'R': 'ﾟΘﾟ',
            'S': 'ﾟДﾟ',
            'T': 'ﾟΘﾟﾉ',
            'U': 'ﾟДﾟﾉ',
            'V': 'ﾟΘﾟ',
            'W': 'ﾟДﾟ',
            'X': 'ﾟΘﾟﾉ',
            'Y': 'ﾟДﾟﾉ',
            'Z': 'ﾟΘﾟ',
            'a': 'ﾟωﾟﾉ',
            'b': 'ﾟΘﾟ',
            'c': 'ﾟДﾟ',
            'd': 'ﾟΘﾟﾉ',
            'e': 'ﾟДﾟﾉ',
            'f': 'ﾟΘﾟ',
            'g': 'ﾟДﾟ',
            'h': 'ﾟΘﾟﾉ',
            'i': 'ﾟДﾟﾉ',
            'j': 'ﾟΘﾟ',
            'k': 'ﾟДﾟ',
            'l': 'ﾟΘﾟﾉ',
            'm': 'ﾟДﾟﾉ',
            'n': 'ﾟΘﾟ',
            'o': 'ﾟДﾟ',
            'p': 'ﾟΘﾟﾉ',
            'q': 'ﾟДﾟﾉ',
            'r': 'ﾟΘﾟ',
            's': 'ﾟДﾟ',
            't': 'ﾟΘﾟﾉ',
            'u': 'ﾟДﾟﾉ',
            'v': 'ﾟΘﾟ',
            'w': 'ﾟДﾟ',
            'x': 'ﾟΘﾟﾉ',
            'y': 'ﾟДﾟﾉ',
            'z': 'ﾟΘﾟ',
            '0': 'ﾟωﾟﾉ',
            '1': 'ﾟΘﾟ',
            '2': 'ﾟДﾟ',
            '3': 'ﾟΘﾟﾉ',
            '4': 'ﾟДﾟﾉ',
            '5': 'ﾟΘﾟ',
            '6': 'ﾟДﾟ',
            '7': 'ﾟΘﾟﾉ',
            '8': 'ﾟДﾟﾉ',
            '9': 'ﾟΘﾟ',
            ' ': 'ﾟωﾟﾉ',
            '!': 'ﾟΘﾟﾉ',
            '"': 'ﾟДﾟﾉ',
            '#': 'ﾟΘﾟ',
            '$': 'ﾟДﾟ',
            '%': 'ﾟΘﾟﾉ',
            '&': 'ﾟДﾟﾉ',
            "'": 'ﾟΘﾟ',
            '(': 'ﾟДﾟ',
            ')': 'ﾟΘﾟﾉ',
            '*': 'ﾟДﾟﾉ',
            '+': 'ﾟΘﾟ',
            ',': 'ﾟДﾟ',
            '-': 'ﾟΘﾟﾉ',
            '.': 'ﾟДﾟﾉ',
            '/': 'ﾟΘﾟ',
            ':': 'ﾟДﾟ',
            ';': 'ﾟΘﾟﾉ',
            '<': 'ﾟДﾟﾉ',
            '=': 'ﾟΘﾟ',
            '>': 'ﾟДﾟ',
            '?': 'ﾟΘﾟﾉ',
            '@': 'ﾟДﾟﾉ',
            '[': 'ﾟΘﾟ',
            '\\': 'ﾟДﾟ',
            ']': 'ﾟΘﾟﾉ',
            '^': 'ﾟДﾟﾉ',
            '_': 'ﾟΘﾟ',
            '`': 'ﾟДﾟ',
            '{': 'ﾟΘﾟﾉ',
            '|': 'ﾟДﾟﾉ',
            '}': 'ﾟΘﾟ',
            '~': 'ﾟДﾟ'
        }
        
        result = []
        for char in text:
            if char in ppencode_map:
                result.append(ppencode_map[char])
            else:
                result.append(f'"{char}"')
        
        return ''.join(result)
    
    @staticmethod
    def ppencode_decode(code: str) -> str:
        raise NotImplementedError("PPencode decoding is not supported due to its complexity")
    
    @staticmethod
    def is_xxencode(text: str) -> bool:
        if not text:
            return False
        text = text.strip()
        return all(c in MiscEncoding.XXENCODE_CHARS for c in text) and len(text) % 4 == 0
    
    @staticmethod
    def is_uuencode(text: str) -> bool:
        if not text:
            return False
        lines = text.strip().split('\n')
        if len(lines) < 2:
            return False
        return all(line.startswith('`') or (len(line) > 0 and ord(line[0]) >= 32 and ord(line[0]) <= 95) for line in lines)
    
    @staticmethod
    def is_jsfuck(text: str) -> bool:
        if not text:
            return False
        jsfuck_patterns = [
            r'\[\]\[(!\[\]\+\[\])',
            r'\(\+!\+\[\]',
            r'\[\]\["entries"\]',
            r'\(false\+\[\]\)',
            r'\(true\+\[\]\)'
        ]
        return any(re.search(pattern, text) for pattern in jsfuck_patterns)
    
    @staticmethod
    def is_brainfuck(text: str) -> bool:
        if not text:
            return False
        brainfuck_chars = set('><+-.,[]')
        return all(c in brainfuck_chars or c.isspace() for c in text) and len([c for c in text if c in brainfuck_chars]) > 0
    
    @staticmethod
    def is_bubble(text: str) -> bool:
        if not text:
            return False
        bubble_patterns = [
            r'ﾟДﾟ',
            r'ﾟΘﾟ',
            r'ﾟωﾟ'
        ]
        return any(re.search(pattern, text) for pattern in bubble_patterns)
    
    @staticmethod
    def is_aaencode(text: str) -> bool:
        if not text:
            return False
        aaencode_patterns = [
            r'ﾟωﾟﾉ',
            r'ﾟΘﾟﾉ',
            r'ﾟДﾟﾉ'
        ]
        return any(re.search(pattern, text) for pattern in aaencode_patterns)
    
    @staticmethod
    def is_jjencode(text: str) -> bool:
        if not text:
            return False
        jjencode_patterns = [
            r'\$[_$]+',
            r'\$\$\$',
            r'\$_\$'
        ]
        return any(re.search(pattern, text) for pattern in jjencode_patterns)
    
    @staticmethod
    def is_ppencode(text: str) -> bool:
        if not text:
            return False
        ppencode_patterns = [
            r'ﾟωﾟﾉ',
            r'ﾟΘﾟﾉ',
            r'ﾟДﾟﾉ'
        ]
        return any(re.search(pattern, text) for pattern in ppencode_patterns)