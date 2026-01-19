# 加密工具 v2.1.0

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
XXencode, UUencode, Brainfuck

### 哈希函数
MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD160

### 进制转换
二进制, 八进制, 十进制, 十六进制

## 更新日志

### v2.1.0 (2026-01-19)

#### 功能变更
- 移除了未实现的编码：JSfuck, Bubble, AAencode, JJencode, PPencode
- 为哈希函数自动禁用解密按钮
- 为Railfence密码添加了栅栏数输入界面
- 实现了所有后台支持的古典密码在GUI中的显示
- 添加了文件导入导出功能
- 添加了操作状态实时反馈

#### 性能优化
- 改进了密钥输入区域布局
- 优化了界面响应速度

#### 问题修复
- 修复了misc_encoding.py中的变量名错误
- 修复了padding_combo的textvariable绑定问题
- 完善了错误提示信息

#### 界面改进
- 重新设计了密钥输入区域，使用分组框组织相关控件
- 添加了操作状态行，显示操作进度和结果
- 改进了错误提示对话框，提供解决建议
- 更新了算法说明页，包含所有支持的算法

## 使用方法

### 使用可执行文件

直接运行 `dist` 目录下的 `crypto_gui.exe` 文件即可启动程序，无需安装 Python 或任何依赖项。

### 从源代码运行

#### 安装依赖
```bash
pip install pycryptodome
```

#### 启动GUI程序
```bash
python crypto_gui.py
```

### 加解密操作

1. 在"加解密"标签页中，从下拉菜单选择加密/解密方式
2. 如果需要密钥或参数，在相应输入框中输入
3. 在"输入文本"区域输入要处理的内容，或点击"📂 导入文件"按钮从文件读取
4. 点击"加密"或"解密"按钮
5. 结果将显示在"结果"区域，状态行显示操作进度
6. 可以点击"📋 复制结果"按钮复制输出内容，或点击"💾 保存结果"按钮保存到文件
7. 点击"🗑️ 清空"按钮清空所有输入输出

### 自动检测加密方式

1. 在"自动检测"标签页中，在"输入密文"区域输入密文
2. 可选：在"密钥输入"区域填写密钥（如果知道的话）
3. 点击"自动检测加密方式"按钮
4. 检测结果将显示在"检测结果"区域
5. 可以点击"复制结果"按钮复制输出内容

### 查看算法说明

1. 在"算法说明"标签页中，可以搜索特定算法
2. 或点击"显示全部"查看所有算法的详细说明
3. 算法按类别分组显示，便于查找

## 注意事项

1. **现代加密算法**（AES, DES, 3DES, RC4）需要密钥
   - AES密钥长度：16/24/32字节
   - DES密钥长度：8字节
   - 3DES密钥长度：16/24字节
   - 支持多种模式：ECB, CBC, CFB, OFB, CTR
   - 支持多种填充方式：ZeroPadding, Pkcs5Padding, Pkcs7Padding, Iso7816Padding, Ansix923Padding

2. **古典密码**可能需要密钥或特定参数
   - Railfence密码需要输入栅栏数（2-10之间）
   - Affine密码需要输入a,b参数（例如：5,8）
   - 部分密码需要特定格式的密钥

3. **哈希函数**是单向的，无法解密
   - 选择哈希函数时，解密按钮会自动禁用

4. **自动检测功能**可能无法识别所有加密类型
   - 建议提供可能的密钥以提高检测成功率
   - 检测结果按可能性排序

5. **文件操作**
   - 支持UTF-8和GBK编码的文件
   - 大文件处理可能需要较长时间

## 兼容性

- 支持Windows 7/8/10/11
- 需要Python 3.8+
- 支持PyCryptodome库

## 版权声明

本项目仅供学习和研究使用。
