import hashlib
from typing import List, Tuple


class HashFunctions:
    HASH_ALGORITHMS = {
        'md5': 'md5',
        'sha1': 'sha1',
        'sha224': 'sha224',
        'sha256': 'sha256',
        'sha384': 'sha384',
        'sha512': 'sha512',
        'sha3_224': 'sha3_224',
        'sha3_256': 'sha3_256',
        'sha3_384': 'sha3_384',
        'sha3_512': 'sha3_512',
        'blake2b': 'blake2b',
        'blake2s': 'blake2s',
        'ripemd160': 'ripemd160'
    }
    
    @staticmethod
    def _compute_hash(text: str, algorithm: str) -> str:
        try:
            if algorithm == 'ripemd160':
                return hashlib.new('ripemd160', text.encode('utf-8')).hexdigest()
            return getattr(hashlib, algorithm)(text.encode('utf-8')).hexdigest()
        except (ValueError, AttributeError):
            raise ValueError(f"{algorithm} algorithm is not available")
    
    @staticmethod
    def md5(text: str) -> str:
        return HashFunctions._compute_hash(text, 'md5')
    
    @staticmethod
    def sha1(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha1')
    
    @staticmethod
    def sha256(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha256')
    
    @staticmethod
    def sha384(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha384')
    
    @staticmethod
    def sha512(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha512')
    
    @staticmethod
    def ripemd(text: str) -> str:
        return HashFunctions._compute_hash(text, 'ripemd160')
    
    @staticmethod
    def ripemd160(text: str) -> str:
        return HashFunctions._compute_hash(text, 'ripemd160')
    
    @staticmethod
    def sha224(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha224')
    
    @staticmethod
    def sha3_224(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha3_224')
    
    @staticmethod
    def sha3_256(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha3_256')
    
    @staticmethod
    def sha3_384(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha3_384')
    
    @staticmethod
    def sha3_512(text: str) -> str:
        return HashFunctions._compute_hash(text, 'sha3_512')
    
    @staticmethod
    def blake2b(text: str) -> str:
        return HashFunctions._compute_hash(text, 'blake2b')
    
    @staticmethod
    def blake2s(text: str) -> str:
        return HashFunctions._compute_hash(text, 'blake2s')
    
    @staticmethod
    def compute_all(text: str) -> List[Tuple[str, str]]:
        results = []
        hash_methods = [
            ('md5', 'MD5'),
            ('sha1', 'SHA1'),
            ('sha224', 'SHA224'),
            ('sha256', 'SHA256'),
            ('sha384', 'SHA384'),
            ('sha512', 'SHA512'),
            ('sha3_224', 'SHA3-224'),
            ('sha3_256', 'SHA3-256'),
            ('sha3_384', 'SHA3-384'),
            ('sha3_512', 'SHA3-512'),
            ('blake2b', 'BLAKE2b'),
            ('blake2s', 'BLAKE2s'),
            ('ripemd160', 'RIPEMD160')
        ]
        
        for method_id, display_name in hash_methods:
            try:
                hash_value = HashFunctions._compute_hash(text, method_id)
                results.append((method_id, display_name, hash_value))
            except:
                pass
        
        return results
    
    @staticmethod
    def _is_hex_string(text: str) -> bool:
        return all(c in '0123456789abcdefABCDEF' for c in text)
    
    @staticmethod
    def is_hash(text: str) -> bool:
        if not text:
            return False
        
        text = text.strip()
        valid_lengths = {32, 40, 56, 64, 96, 128}
        return len(text) in valid_lengths and HashFunctions._is_hex_string(text)
    
    @staticmethod
    def detect_hash_type(text: str) -> List[Tuple[str, str]]:
        if not text:
            return []
        
        text = text.strip()
        results = []
        
        hash_types = {
            32: [('md5', 'MD5')],
            40: [('sha1', 'SHA1')],
            56: [('sha224', 'SHA224')],
            64: [('sha256', 'SHA256'), ('sha3_256', 'SHA3-256')],
            96: [('sha384', 'SHA384'), ('sha3_384', 'SHA3-384')],
            128: [('sha512', 'SHA512'), ('sha3_512', 'SHA3-512')]
        }
        
        if len(text) in hash_types and HashFunctions._is_hex_string(text):
            results.extend(hash_types[len(text)])
        
        return results