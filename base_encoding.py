import base64

class BaseEncoding:
    BASE16 = '0123456789ABCDEF'
    BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    BASE36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    BASE85 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
    BASE91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~"'
    BASE92 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~"\''

    @staticmethod
    def _base_encode_generic(text: str, chars: str) -> str:
        num = int.from_bytes(text.encode('utf-8'), 'big')
        if num == 0:
            return chars[0]
        result = []
        base = len(chars)
        while num > 0:
            num, remainder = divmod(num, base)
            result.append(chars[remainder])
        return ''.join(reversed(result))

    @staticmethod
    def _base_decode_generic(text: str, chars: str) -> str:
        num = 0
        base = len(chars)
        for char in text:
            num = num * base + chars.index(char)
        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, 'big').decode('utf-8', errors='ignore')

    @staticmethod
    def _base91_92_encode(text: str, chars: str, base: int) -> str:
        b = 0
        n = 0
        out = []
        for c in text.encode('utf-8'):
            b |= c << n
            n += 8
            if n > 13:
                v = b & 8191
                if v > 88:
                    b >>= 13
                    n -= 13
                else:
                    v = b & 16383
                    b >>= 14
                    n -= 14
                out.append(chars[v % base])
                out.append(chars[v // base])
        if n > 0:
            out.append(chars[b % base])
            if n > 7 or b > base - 1:
                out.append(chars[b // base])
        return ''.join(out)

    @staticmethod
    def _base91_92_decode(text: str, chars: str, base: int) -> str:
        v = -1
        b = 0
        n = 0
        out = []
        for c in text:
            if c not in chars:
                continue
            i = chars.index(c)
            if v < 0:
                v = i
            else:
                v += i * base
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append((b & 255))
                    b >>= 8
                    n -= 8
                v = -1
        if v + 1:
            out.append((b | v << n))
        return bytes(out).decode('utf-8', errors='ignore')

    @staticmethod
    def base16_encode(text: str) -> str:
        return base64.b16encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def base16_decode(text: str) -> str:
        return base64.b16decode(text, validate=True).decode('utf-8')

    @staticmethod
    def base32_encode(text: str) -> str:
        return base64.b32encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def base32_decode(text: str) -> str:
        return base64.b32decode(text, casefold=True).decode('utf-8')

    @staticmethod
    def base36_encode(text: str) -> str:
        return BaseEncoding._base_encode_generic(text, BaseEncoding.BASE36)

    @staticmethod
    def base36_decode(text: str) -> str:
        return BaseEncoding._base_decode_generic(text.upper(), BaseEncoding.BASE36)

    @staticmethod
    def base58_encode(text: str) -> str:
        return BaseEncoding._base_encode_generic(text, BaseEncoding.BASE58)

    @staticmethod
    def base58_decode(text: str) -> str:
        return BaseEncoding._base_decode_generic(text, BaseEncoding.BASE58)

    @staticmethod
    def base62_encode(text: str) -> str:
        return BaseEncoding._base_encode_generic(text, BaseEncoding.BASE62)

    @staticmethod
    def base62_decode(text: str) -> str:
        return BaseEncoding._base_decode_generic(text, BaseEncoding.BASE62)

    @staticmethod
    def base64_encode(text: str) -> str:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def base64_decode(text: str) -> str:
        return base64.b64decode(text).decode('utf-8')

    @staticmethod
    def base85_encode(text: str) -> str:
        return base64.b85encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def base85_decode(text: str) -> str:
        return base64.b85decode(text).decode('utf-8')

    @staticmethod
    def base91_encode(text: str) -> str:
        return BaseEncoding._base91_92_encode(text, BaseEncoding.BASE91, 91)

    @staticmethod
    def base91_decode(text: str) -> str:
        return BaseEncoding._base91_92_decode(text, BaseEncoding.BASE91, 91)

    @staticmethod
    def base92_encode(text: str) -> str:
        return BaseEncoding._base91_92_encode(text, BaseEncoding.BASE92, 92)

    @staticmethod
    def base92_decode(text: str) -> str:
        return BaseEncoding._base91_92_decode(text, BaseEncoding.BASE92, 92)
