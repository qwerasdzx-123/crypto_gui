from typing import List, Tuple


class BaseConversion:
    @staticmethod
    def text_to_binary(text: str) -> str:
        return ' '.join(format(ord(char), '08b') for char in text)
    
    @staticmethod
    def binary_to_text(binary: str) -> str:
        binary = binary.replace(' ', '')
        bytes_list = [binary[i:i+8] for i in range(0, len(binary), 8)]
        return ''.join(chr(int(byte, 2)) for byte in bytes_list if byte)
    
    @staticmethod
    def text_to_octal(text: str) -> str:
        return ' '.join(format(ord(char), '03o') for char in text)
    
    @staticmethod
    def octal_to_text(octal: str) -> str:
        octal = octal.replace(' ', '')
        bytes_list = [octal[i:i+3] for i in range(0, len(octal), 3)]
        return ''.join(chr(int(byte, 8)) for byte in bytes_list if byte)
    
    @staticmethod
    def text_to_decimal(text: str) -> str:
        return ' '.join(str(ord(char)) for char in text)
    
    @staticmethod
    def decimal_to_text(decimal: str) -> str:
        decimal = decimal.strip()
        if not decimal:
            return ""
        
        # 支持空格或逗号分隔的数字
        import re
        numbers = re.split(r'[,\s]+', decimal)
        result = []
        
        for num_str in numbers:
            if not num_str:  # 跳过空字符串
                continue
            try:
                num = int(num_str)
                if 0 <= num <= 127:  # ASCII范围
                    result.append(chr(num))
                else:
                    result.append(f"[{num}]")  # 超出ASCII范围的数字标记
            except ValueError:
                result.append(f"[{num_str}]")  # 无效数字标记
        
        return ''.join(result)
    
    @staticmethod
    def text_to_hexadecimal(text: str) -> str:
        return ' '.join(format(ord(char), '02x') for char in text)
    
    @staticmethod
    def hexadecimal_to_text(hexadecimal: str) -> str:
        hexadecimal = hexadecimal.replace(' ', '')
        bytes_list = [hexadecimal[i:i+2] for i in range(0, len(hexadecimal), 2)]
        return ''.join(chr(int(byte, 16)) for byte in bytes_list if byte)
    
    @staticmethod
    def binary_to_octal(binary: str) -> str:
        text = BaseConversion.binary_to_text(binary)
        return BaseConversion.text_to_octal(text)
    
    @staticmethod
    def octal_to_binary(octal: str) -> str:
        text = BaseConversion.octal_to_text(octal)
        return BaseConversion.text_to_binary(text)
    
    @staticmethod
    def binary_to_decimal(binary: str) -> str:
        text = BaseConversion.binary_to_text(binary)
        return BaseConversion.text_to_decimal(text)
    
    @staticmethod
    def decimal_to_binary(decimal: str) -> str:
        text = BaseConversion.decimal_to_text(decimal)
        return BaseConversion.text_to_binary(text)
    
    @staticmethod
    def binary_to_hexadecimal(binary: str) -> str:
        text = BaseConversion.binary_to_text(binary)
        return BaseConversion.text_to_hexadecimal(text)
    
    @staticmethod
    def hexadecimal_to_binary(hexadecimal: str) -> str:
        text = BaseConversion.hexadecimal_to_text(hexadecimal)
        return BaseConversion.text_to_binary(text)
    
    @staticmethod
    def octal_to_decimal(octal: str) -> str:
        text = BaseConversion.octal_to_text(octal)
        return BaseConversion.text_to_decimal(text)
    
    @staticmethod
    def decimal_to_octal(decimal: str) -> str:
        text = BaseConversion.decimal_to_text(decimal)
        return BaseConversion.text_to_octal(text)
    
    @staticmethod
    def octal_to_hexadecimal(octal: str) -> str:
        text = BaseConversion.octal_to_text(octal)
        return BaseConversion.text_to_hexadecimal(text)
    
    @staticmethod
    def hexadecimal_to_octal(hexadecimal: str) -> str:
        text = BaseConversion.hexadecimal_to_text(hexadecimal)
        return BaseConversion.text_to_octal(text)
    
    @staticmethod
    def decimal_to_hexadecimal(decimal: str) -> str:
        text = BaseConversion.decimal_to_text(decimal)
        return BaseConversion.text_to_hexadecimal(text)
    
    @staticmethod
    def hexadecimal_to_decimal(hexadecimal: str) -> str:
        text = BaseConversion.hexadecimal_to_text(hexadecimal)
        return BaseConversion.text_to_decimal(text)
    
    @staticmethod
    def convert_all(text: str) -> List[Tuple[str, str, str]]:
        results = []
        
        try:
            results.append(('binary', '二进制', BaseConversion.text_to_binary(text)))
        except:
            pass
        
        try:
            results.append(('octal', '八进制', BaseConversion.text_to_octal(text)))
        except:
            pass
        
        try:
            results.append(('decimal', '十进制', BaseConversion.text_to_decimal(text)))
        except:
            pass
        
        try:
            results.append(('hexadecimal', '十六进制', BaseConversion.text_to_hexadecimal(text)))
        except:
            pass
        
        return results
    
    @staticmethod
    def is_binary(text: str) -> bool:
        if not text:
            return False
        text = text.replace(' ', '')
        return all(c in '01' for c in text) and len(text) % 8 == 0
    
    @staticmethod
    def is_octal(text: str) -> bool:
        if not text:
            return False
        text = text.replace(' ', '')
        return all(c in '01234567' for c in text) and len(text) % 3 == 0
    
    @staticmethod
    def is_decimal(text: str) -> bool:
        if not text:
            return False
        text = text.replace(' ', '')
        return all(c.isdigit() for c in text)
    
    @staticmethod
    def is_hexadecimal(text: str) -> bool:
        if not text:
            return False
        text = text.replace(' ', '')
        return all(c in '0123456789abcdefABCDEF' for c in text) and len(text) % 2 == 0
    
    @staticmethod
    def detect_base(text: str) -> List[Tuple[str, str]]:
        if not text:
            return []
        
        results = []
        
        if BaseConversion.is_binary(text):
            results.append(('binary', '二进制'))
        
        if BaseConversion.is_octal(text):
            results.append(('octal', '八进制'))
        
        if BaseConversion.is_decimal(text):
            results.append(('decimal', '十进制'))
        
        if BaseConversion.is_hexadecimal(text):
            results.append(('hexadecimal', '十六进制'))
        
        return results