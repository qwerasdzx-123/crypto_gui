# 加密工具

一个功能强大的 Python 加密/解密工具，支持多种加密算法、编码方式和哈希函数。

## 功能特性

### Base 编码
Base16, Base32, Base36, Base58, Base62, Base64, Base85, Base91, Base92

### 编码转换
Hex, URL, HTML, Escape, ASCII, Quoted-printable

### 古典密码
Caesar, Vigenère, ROT13, Atbash, Affine, Railfence, Playfair, Beaufort, Porta, Autokey, Running Key, Columnar, A1Z26, ADFGX, ADFGVX, Bifid, Four-Square, Gronsfeld, Keyword, Simple Substitution

### 现代加密
AES (ECB, CBC, CFB, OFB, CTR), DES, 3DES, RC4

### 特殊编码
Morse Code, Tapcode, Pigpen, Baconian

### 其他编码
XXencode, UUencode, JSfuck, Brainfuck, Bubble, AAencode, JJencode, PPencode

### 哈希函数
MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD160

### 进制转换
二进制, 八进制, 十进制, 十六进制

## 安装

### 依赖项
- Python 3.7+
- pycryptodome

### 安装依赖
```bash
pip install pycryptodome
```

## 使用方法

### 启动GUI程序

```bash
python crypto_gui.py
```

### 加解密操作

1. 在"加解密"标签页中，从下拉菜单选择加密/解密方式
2. 如果需要密钥，在"密钥"输入框中输入相应参数
3. 在"输入文本"区域输入要处理的内容
4. 点击"加密"或"解密"按钮
5. 结果将显示在"结果"区域
6. 可以点击"复制结果"按钮复制输出内容

### 自动检测加密方式

1. 在"自动检测"标签页中，在"输入密文"区域输入密文
2. 可选：在"密钥输入"区域填写密钥（如果知道的话）
3. 点击"自动检测加密方式"按钮
4. 检测结果将显示在"检测结果"区域
5. 可以点击"复制结果"按钮复制输出内容

### 查看算法说明

1. 在"算法说明"标签页中，可以搜索特定算法
2. 或点击"显示全部"查看所有算法的详细说明

## 注意事项

1. 现代加密算法（AES, DES, 3DES, RC4）需要密钥
2. AES密钥长度：16/24/32字节
3. DES密钥长度：8字节
4. 3DES密钥长度：16/24字节
5. 某些古典密码需要密钥或特定参数
6. 自动检测功能可能无法识别所有加密类型
7. 对于某些编码方式，解密可能需要特定的参数

## 版权声明

本项目仅供学习和研究使用。
