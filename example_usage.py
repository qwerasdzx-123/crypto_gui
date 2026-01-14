#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto_tool import CryptoTool

def main():
    tool = CryptoTool()
    
    print("=" * 60)
    print("加密工具使用示例")
    print("=" * 60)
    
    # 示例1: Base编码
    print("\n[示例1] Base编码")
    text = "Hello World"
    print(f"原文: {text}")
    print(f"Base64编码: {tool.base64_encode(text)}")
    print(f"Base32编码: {tool.base32_encode(text)}")
    print(f"Base16编码: {tool.base16_encode(text)}")
    
    # 示例2: 编码转换
    print("\n[示例2] 编码转换")
    text = "Hello World 测试"
    print(f"原文: {text}")
    print(f"Hex编码: {tool.hex_encode(text)}")
    print(f"URL编码: {tool.url_encode(text)}")
    print(f"HTML编码: {tool.html_encode(text)}")
    
    # 示例3: 古典密码
    print("\n[示例3] 古典密码")
    text = "Hello World"
    print(f"原文: {text}")
    print(f"Caesar加密(偏移3): {tool.caesar_encrypt(text, 3)}")
    print(f"Vigenère加密(密钥KEY): {tool.vigenere_encrypt(text, 'KEY')}")
    print(f"ROT13加密: {tool.rot13_encrypt(text)}")
    print(f"Atbash加密: {tool.atbash_encrypt(text)}")
    print(f"Affine加密(a=5,b=8): {tool.affine_encrypt(text, 5, 8)}")
    
    # 示例4: 特殊编码
    print("\n[示例4] 特殊编码")
    text = "SOS"
    print(f"原文: {text}")
    print(f"莫尔斯电码: {tool.morse_encode(text)}")
    print(f"A1Z26编码: {tool.a1z26_encode('HELLO')}")
    
    # 示例5: 哈希函数
    print("\n[示例5] 哈希函数")
    text = "Hello World"
    print(f"原文: {text}")
    print(f"MD5: {tool.md5_hash(text)}")
    print(f"SHA1: {tool.sha1_hash(text)}")
    print(f"SHA256: {tool.sha256_hash(text)}")
    print(f"SHA512: {tool.sha512_hash(text)}")
    
    # 示例6: 进制转换
    print("\n[示例6] 进制转换")
    text = "ABC"
    print(f"原文: {text}")
    print(f"二进制: {tool.binary_encode(text)}")
    print(f"八进制: {tool.octal_encode(text)}")
    print(f"十进制: {tool.decimal_encode(text)}")
    print(f"十六进制: {tool.hex_encode(text)}")
    
    # 示例7: 现代加密
    print("\n[示例7] 现代加密")
    text = "Hello World"
    key = "1234567890123456"
    print(f"原文: {text}")
    print(f"AES加密: {tool.aes_encrypt(text, key)}")
    
    key = "12345678"
    print(f"DES加密: {tool.des_encrypt(text, key)}")
    
    # 示例8: 自动检测
    print("\n[示例8] 自动检测")
    ciphertext = "SGVsbG8gV29ybGQ="
    print(f"密文: {ciphertext}")
    results = tool.auto_detect(ciphertext)
    print("可能的加密方式:")
    for method, name, decoded in results:
        print(f"  - {method} ({name}): {decoded}")
    
    # 示例9: 统一加密/解密接口
    print("\n[示例9] 统一加密/解密接口")
    text = "Hello World"
    print(f"原文: {text}")
    
    encrypted = tool.encrypt('base64', text)
    print(f"base64加密: {encrypted}")
    print(f"base64解密: {tool.decrypt('base64', encrypted)}")
    
    encrypted = tool.encrypt('caesar', text, shift=5)
    print(f"caesar加密(偏移5): {encrypted}")
    print(f"caesar解密: {tool.decrypt('caesar', encrypted, shift=5)}")
    
    encrypted = tool.encrypt('vigenere', text, key='SECRET')
    print(f"vigenere加密(密钥SECRET): {encrypted}")
    print(f"vigenere解密: {tool.decrypt('vigenere', encrypted, key='SECRET')}")
    
    # 示例10: 批量检测
    print("\n[示例10] 批量检测多个密文")
    ciphertexts = [
        "SGVsbG8gV29ybGQ=",
        "48656c6c6f20576f726c64",
        "... --- ...",
        "Khoor Zruog"
    ]
    
    for ciphertext in ciphertexts:
        print(f"\n密文: {ciphertext}")
        results = tool.auto_detect(ciphertext)
        for method, name, decoded in results:
            print(f"  - {method} ({name}): {decoded}")
    
    print("\n" + "=" * 60)
    print("示例演示完成!")
    print("=" * 60)

if __name__ == "__main__":
    main()
