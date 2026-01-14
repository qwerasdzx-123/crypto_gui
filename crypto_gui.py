#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from crypto_tool import CryptoTool
import threading


class MacOSStyle:
    def __init__(self):
        self.colors = {
            'background': '#f5f5f7',
            'card': '#ffffff',
            'card_border': '#e0e0e0',
            'text': '#1d1d1f',
            'text_secondary': '#86868b',
            'accent': '#007aff',
            'accent_hover': '#0051d5',
            'success': '#34c759',
            'warning': '#ff9500',
            'error': '#ff3b30',
            'border': '#d2d2d7'
        }
        self.fonts = {
            'title': ('SF Pro Display', 20, 'bold'),
            'heading': ('SF Pro Display', 14, 'bold'),
            'body': ('SF Pro Text', 12),
            'small': ('SF Pro Text', 10),
            'code': ('Menlo', 11)
        }


class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("加密工具 - Crypto Tool")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        self.style = MacOSStyle()
        self.tool = CryptoTool()
        
        self.method_mapping = {
            "Base 编码": None,
            "Base16": "base16",
            "Base32": "base32",
            "Base36": "base36",
            "Base58": "base58",
            "Base62": "base62",
            "Base64": "base64",
            "Base85": "base85",
            "Base91": "base91",
            "Base92": "base92",
            "编码转换": None,
            "Hex": "hex",
            "URL编码": "url",
            "HTML编码": "html",
            "Escape编码": "escape",
            "ASCII编码": "ascii",
            "Quoted编码": "quoted",
            "古典密码": None,
            "Caesar密码": "caesar",
            "Vigenère密码": "vigenere",
            "ROT13": "rot13",
            "Atbash密码": "atbash",
            "Affine密码": "affine",
            "Railfence密码": "railfence",
            "A1Z26": "a1z26",
            "Playfair密码": "playfair",
            "现代加密": None,
            "AES加密": "aes",
            "DES加密": "des",
            "3DES加密": "3des",
            "RC4加密": "rc4",
            "特殊编码": None,
            "Morse密码": "morse",
            "Tapcode": "tapcode",
            "猪圈密码": "pigpen",
            "Baconian密码": "baconian",
            "其他编码": None,
            "XXencode": "xxencode",
            "UUencode": "uuencode",
            "JSfuck": "jsfuck",
            "Brainfuck": "brainfuck",
            "Bubble编码": "bubble",
            "AAencode": "aaencode",
            "JJencode": "jjencode",
            "PPencode": "ppencode",
            "进制转换": None,
            "二进制": "binary",
            "八进制": "octal",
            "十进制": "decimal",
            "十六进制": "hexadecimal",
            "哈希函数": None,
            "MD5": "md5",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SHA384": "sha384",
            "SHA512": "sha512",
            "RIPEMD160": "ripemd160"
        }
        
        self.key_requirements = {
            'caesar': {'type': 'shift', 'label': '移位值', 'default': 3},
            'vigenere': {'type': 'text', 'label': '密钥', 'default': ''},
            'affine': {'type': 'affine', 'label': '参数', 'default': '5,8'},
            'playfair': {'type': 'text', 'label': '密钥', 'default': ''},
            'beaufort': {'type': 'text', 'label': '密钥', 'default': ''},
            'porta': {'type': 'text', 'label': '密钥', 'default': ''},
            'autokey': {'type': 'text', 'label': '密钥', 'default': ''},
            'bifid': {'type': 'text', 'label': '密钥', 'default': ''},
            'four': {'type': 'text', 'label': '密钥', 'default': ''},
            'gronsfeld': {'type': 'text', 'label': '密钥', 'default': ''},
            'keyword': {'type': 'text', 'label': '密钥', 'default': ''},
            'runkey': {'type': 'text', 'label': '密钥', 'default': ''},
            'simple': {'type': 'text', 'label': '密钥', 'default': ''},
            'columnar': {'type': 'text', 'label': '密钥', 'default': ''},
            'aes': {'type': 'aes', 'label': '密钥', 'default': ''},
            'des': {'type': 'des', 'label': '密钥', 'default': ''},
            '3des': {'type': '3des', 'label': '密钥', 'default': ''},
            'rc4': {'type': 'text', 'label': '密钥', 'default': ''}
        }
        
        self.setup_styles()
        self.setup_ui()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background=self.style.colors['background'])
        style.configure('Card.TFrame', background=self.style.colors['card'], relief='flat')
        style.configure('TNotebook', background=self.style.colors['background'], borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=self.style.colors['background'],
                       foreground=self.style.colors['text_secondary'],
                       padding=[20, 10],
                       borderwidth=0)
        style.map('TNotebook.Tab',
                 background=[('selected', self.style.colors['card'])],
                 foreground=[('selected', self.style.colors['text'])])
        
        style.configure('TLabel', 
                       background=self.style.colors['card'],
                       foreground=self.style.colors['text'],
                       font=self.style.fonts['body'])
        style.configure('Heading.TLabel', 
                       background=self.style.colors['card'],
                       foreground=self.style.colors['text'],
                       font=self.style.fonts['heading'])
        style.configure('Secondary.TLabel', 
                       background=self.style.colors['card'],
                       foreground=self.style.colors['text_secondary'],
                       font=self.style.fonts['small'])
        
        style.configure('TButton',
                       background=self.style.colors['accent'],
                       foreground='white',
                       borderwidth=0,
                       relief='flat',
                       padding=[15, 8],
                       font=self.style.fonts['body'])
        style.map('TButton',
                 background=[('active', self.style.colors['accent_hover'])])
        
        style.configure('Secondary.TButton',
                       background=self.style.colors['background'],
                       foreground=self.style.colors['text'],
                       borderwidth=1,
                       relief='solid',
                       padding=[15, 8],
                       font=self.style.fonts['body'])
        
        style.configure('TCombobox',
                       fieldbackground=self.style.colors['card'],
                       background=self.style.colors['card'],
                       borderwidth=1,
                       relief='solid',
                       padding=[10, 5])
        
        style.configure('TEntry',
                       fieldbackground=self.style.colors['card'],
                       background=self.style.colors['card'],
                       borderwidth=1,
                       relief='solid',
                       padding=[10, 5])
        
        style.configure('TProgressbar',
                       background=self.style.colors['accent'],
                       troughcolor=self.style.colors['background'],
                       borderwidth=0,
                       thickness=3)
        
    def create_card(self, parent, padding=20):
        card = ttk.Frame(parent, style='Card.TFrame', padding=padding)
        return card
        
    def setup_ui(self):
        main_container = ttk.Frame(self.root, style='TFrame')
        main_container.pack(fill='both', expand=True)
        
        notebook = ttk.Notebook(main_container, style='TNotebook')
        notebook.pack(fill='both', expand=True, padx=30, pady=30)
        
        self.encrypt_tab = ttk.Frame(notebook, style='TFrame')
        self.detect_tab = ttk.Frame(notebook, style='TFrame')
        self.help_tab = ttk.Frame(notebook, style='TFrame')
        
        notebook.add(self.encrypt_tab, text='  加解密  ')
        notebook.add(self.detect_tab, text='  自动检测  ')
        notebook.add(self.help_tab, text='  算法说明  ')
        
        self.setup_encrypt_tab()
        self.setup_detect_tab()
        self.setup_help_tab()
        
    def setup_encrypt_tab(self):
        main_frame = ttk.Frame(self.encrypt_tab, style='TFrame')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        card = self.create_card(main_frame)
        card.pack(fill='both', expand=True)
        
        ttk.Label(card, text="选择加密/解密方式", style='Heading.TLabel').pack(anchor='w', pady=(0, 10))
        
        self.method_var = tk.StringVar()
        method_frame = ttk.Frame(card, style='Card.TFrame')
        method_frame.pack(fill='x', pady=(0, 15))
        
        self.method_combo = ttk.Combobox(method_frame, textvariable=self.method_var, state='readonly', font=self.style.fonts['body'])
        self.method_combo.pack(side='left', fill='x', expand=True)
        self.method_combo.bind('<<ComboboxSelected>>', self.on_method_changed)
        
        self.load_methods()
        
        self.key_frame = ttk.Frame(card, style='Card.TFrame')
        self.key_frame.pack(fill='x', pady=(0, 15))
        
        self.key_label = ttk.Label(self.key_frame, text="密钥:", style='TLabel')
        self.key_label.pack(anchor='w', pady=(0, 5))
        
        self.key_entry = ttk.Entry(self.key_frame, font=self.style.fonts['body'])
        self.key_entry.pack(fill='x')
        
        self.key_info_label = ttk.Label(self.key_frame, text="", style='Secondary.TLabel')
        self.key_info_label.pack(anchor='w', pady=(5, 0))
        
        self.key_frame.pack_forget()
        
        ttk.Label(card, text="输入文本", style='Heading.TLabel').pack(anchor='w', pady=(10, 5))
        
        self.input_text = scrolledtext.ScrolledText(card, height=10, wrap=tk.WORD, 
                                                   font=self.style.fonts['code'],
                                                   bg=self.style.colors['background'],
                                                   fg=self.style.colors['text'],
                                                   insertbackground=self.style.colors['accent'],
                                                   relief='flat',
                                                   padx=15, pady=15)
        self.input_text.pack(fill='both', expand=True, pady=(0, 15))
        
        button_frame = ttk.Frame(card, style='Card.TFrame')
        button_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Button(button_frame, text="加密", command=self.encrypt_text, style='TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="解密", command=self.decrypt_text, style='TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="清空", command=self.clear_encrypt, style='Secondary.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="复制结果", command=self.copy_result, style='Secondary.TButton').pack(side='right')
        
        ttk.Label(card, text="结果", style='Heading.TLabel').pack(anchor='w', pady=(10, 5))
        
        self.output_text = scrolledtext.ScrolledText(card, height=10, wrap=tk.WORD,
                                                    font=self.style.fonts['code'],
                                                    bg=self.style.colors['background'],
                                                    fg=self.style.colors['text'],
                                                    insertbackground=self.style.colors['accent'],
                                                    relief='flat',
                                                    padx=15, pady=15)
        self.output_text.pack(fill='both', expand=True)
        
    def setup_detect_tab(self):
        main_frame = ttk.Frame(self.detect_tab, style='TFrame')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        card = self.create_card(main_frame)
        card.pack(fill='both', expand=True)
        
        ttk.Label(card, text="输入密文", style='Heading.TLabel').pack(anchor='w', pady=(0, 10))
        
        self.detect_input = scrolledtext.ScrolledText(card, height=8, wrap=tk.WORD,
                                                      font=self.style.fonts['code'],
                                                      bg=self.style.colors['background'],
                                                      fg=self.style.colors['text'],
                                                      insertbackground=self.style.colors['accent'],
                                                      relief='flat',
                                                      padx=15, pady=15)
        self.detect_input.pack(fill='both', expand=True, pady=(0, 15))
        
        button_frame = ttk.Frame(card, style='Card.TFrame')
        button_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Button(button_frame, text="自动检测加密方式", command=self.detect_encryption, style='TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="清空", command=self.clear_detect, style='Secondary.TButton').pack(side='left')
        
        ttk.Label(card, text="检测结果", style='Heading.TLabel').pack(anchor='w', pady=(10, 5))
        
        self.detect_output = scrolledtext.ScrolledText(card, height=12, wrap=tk.WORD,
                                                       font=self.style.fonts['code'],
                                                       bg=self.style.colors['background'],
                                                       fg=self.style.colors['text'],
                                                       insertbackground=self.style.colors['accent'],
                                                       relief='flat',
                                                       padx=15, pady=15)
        self.detect_output.pack(fill='both', expand=True, pady=(0, 15))
        
        ttk.Label(card, text="密钥输入（可选）", style='Heading.TLabel').pack(anchor='w', pady=(10, 5))
        
        detect_key_frame = ttk.Frame(card, style='Card.TFrame')
        detect_key_frame.pack(fill='x', pady=(0, 15))
        
        self.detect_key_label = ttk.Label(detect_key_frame, text="密钥/移位值:", style='TLabel')
        self.detect_key_label.pack(anchor='w', pady=(0, 5))
        
        self.detect_key_entry = ttk.Entry(detect_key_frame, font=self.style.fonts['body'])
        self.detect_key_entry.pack(fill='x', pady=(0, 5))
        
        self.detect_key_info_label = ttk.Label(detect_key_frame, 
                                                text="提示: 如果填写了密钥，将尝试所有需要密钥的解密方式；如果不填写，只尝试不需要密钥的解密方式。", 
                                                style='Secondary.TLabel')
        self.detect_key_info_label.pack(anchor='w', pady=(5, 0))
        
        detect_button_frame = ttk.Frame(card, style='Card.TFrame')
        detect_button_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Button(detect_button_frame, text="复制结果", command=self.copy_detect_result, style='Secondary.TButton').pack(side='left')
        
        progress_frame = ttk.Frame(card, style='Card.TFrame')
        progress_frame.pack(fill='x', pady=(15, 0))
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate', style='TProgressbar')
        self.progress.pack(fill='x')
        
        self.status_label = ttk.Label(progress_frame, text="就绪", style='Secondary.TLabel')
        self.status_label.pack(pady=(8, 0))
        
    def setup_help_tab(self):
        main_frame = ttk.Frame(self.help_tab, style='TFrame')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        card = self.create_card(main_frame)
        card.pack(fill='both', expand=True)
        
        search_frame = ttk.Frame(card, style='Card.TFrame')
        search_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Label(search_frame, text="搜索:", style='TLabel').pack(side='left', padx=(0, 10))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=self.style.fonts['body'])
        search_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        ttk.Button(search_frame, text="搜索", command=self.search_algorithms, style='TButton').pack(side='left', padx=(0, 10))
        ttk.Button(search_frame, text="显示全部", command=self.show_all_algorithms, style='Secondary.TButton').pack(side='left')
        
        self.help_text = scrolledtext.ScrolledText(card, wrap=tk.WORD,
                                                   font=self.style.fonts['body'],
                                                   bg=self.style.colors['background'],
                                                   fg=self.style.colors['text'],
                                                   insertbackground=self.style.colors['accent'],
                                                   relief='flat',
                                                   padx=20, pady=20)
        self.help_text.pack(fill='both', expand=True)
        
        self.show_all_algorithms()
        
    def load_methods(self):
        methods = [
            "Base 编码",
            "Base16", "Base32", "Base36", "Base58", "Base62", 
            "Base64", "Base85", "Base91", "Base92",
            "编码转换",
            "Hex", "URL编码", "HTML编码", "Escape编码", 
            "ASCII编码", "Quoted编码",
            "古典密码",
            "Caesar密码", "Vigenère密码", "ROT13", "Atbash密码",
            "Affine密码", "Railfence密码", "A1Z26", "Playfair密码",
            "现代加密",
            "AES加密", "DES加密", "3DES加密", "RC4加密",
            "特殊编码",
            "Morse密码", "Tapcode", "猪圈密码", "Baconian密码",
            "其他编码",
            "XXencode", "UUencode", "JSfuck", "Brainfuck",
            "Bubble编码", "AAencode", "JJencode", "PPencode",
            "进制转换",
            "二进制", "八进制", "十进制", "十六进制",
            "哈希函数",
            "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "RIPEMD160"
        ]
        
        self.method_combo['values'] = methods
        if methods:
            self.method_combo.current(0)
            
    def on_method_changed(self, event):
        method_display = self.method_var.get()
        method = self.method_mapping.get(method_display)
        
        if method in self.key_requirements:
            self.key_frame.pack(fill='x', pady=(0, 15), after=self.method_combo.master)
            req = self.key_requirements[method]
            self.key_label.config(text=f"{req['label']}:")
            
            if req['type'] == 'shift':
                self.key_info_label.config(text="请输入移位值（整数）")
            elif req['type'] == 'affine':
                self.key_info_label.config(text="请输入a,b参数（例如：5,8）")
            elif req['type'] in ['aes', 'des', '3des']:
                if req['type'] == 'aes':
                    self.key_info_label.config(text="请输入密钥（16/24/32字节）")
                elif req['type'] == 'des':
                    self.key_info_label.config(text="请输入密钥（8字节）")
                elif req['type'] == '3des':
                    self.key_info_label.config(text="请输入密钥（16/24字节）")
            else:
                self.key_info_label.config(text="请输入密钥文本")
        else:
            self.key_frame.pack_forget()
            
    def get_key_params(self, method):
        if method not in self.key_requirements:
            return {}
        
        req = self.key_requirements[method]
        key_value = self.key_entry.get().strip()
        
        if req['type'] == 'shift':
            try:
                shift = int(key_value) if key_value else req['default']
                return {'shift': shift}
            except ValueError:
                return {'shift': req['default']}
        elif req['type'] == 'affine':
            try:
                parts = key_value.split(',')
                if len(parts) == 2:
                    a = int(parts[0].strip())
                    b = int(parts[1].strip())
                    return {'a': a, 'b': b}
                else:
                    default_parts = req['default'].split(',')
                    return {'a': int(default_parts[0]), 'b': int(default_parts[1])}
            except ValueError:
                default_parts = req['default'].split(',')
                return {'a': int(default_parts[0]), 'b': int(default_parts[1])}
        elif req['type'] in ['aes', 'des', '3des']:
            return {'key': key_value if key_value else req['default']}
        else:
            return {'key': key_value if key_value else req['default']}
            
    def encrypt_text(self):
        method_display = self.method_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("警告", "请输入要加密的文本！")
            return
            
        if not method_display:
            messagebox.showwarning("警告", "请选择加密方式！")
            return
        
        method = self.method_mapping.get(method_display)
        if method is None:
            messagebox.showwarning("警告", "请选择一个具体的加密方式，而不是分类！")
            return
        
        key_params = self.get_key_params(method)
            
        try:
            result = self.tool.encrypt(method, text, **key_params)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
            
    def decrypt_text(self):
        method_display = self.method_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("警告", "请输入要解密的文本！")
            return
            
        if not method_display:
            messagebox.showwarning("警告", "请选择解密方式！")
            return
        
        method = self.method_mapping.get(method_display)
        if method is None:
            messagebox.showwarning("警告", "请选择一个具体的解密方式，而不是分类！")
            return
        
        key_params = self.get_key_params(method)
            
        try:
            result = self.tool.decrypt(method, text, **key_params)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
            
    def clear_encrypt(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        
    def copy_result(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("成功", "结果已复制到剪贴板！")
            
    def detect_encryption(self):
        text = self.detect_input.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("警告", "请输入要检测的密文！")
            return
            
        key = self.detect_key_entry.get().strip()
        
        self.detect_output.delete("1.0", tk.END)
        self.progress.start()
        self.status_label.config(text="正在检测...")
        
        def detect_thread():
            try:
                results = self.tool.auto_detect(text, key)
                
                self.root.after(0, self.display_detect_results, results)
            except Exception as e:
                self.root.after(0, lambda: self.display_detect_error(str(e)))
                
        thread = threading.Thread(target=detect_thread)
        thread.daemon = True
        thread.start()
        
    def display_detect_results(self, results):
        self.progress.stop()
        self.status_label.config(text="检测完成")
        
        self.detect_output.delete("1.0", tk.END)
        self.detect_output.insert("1.0", "=" * 80 + "\n\n")
        
        if not results:
            self.detect_output.insert(tk.END, "未检测到已知的加密方式。\n\n")
            self.detect_output.insert(tk.END, "提示: 请确保输入的是完整的密文，某些加密方式需要特定的格式。\n")
        else:
            self.detect_output.insert(tk.END, f"检测到 {len(results)} 种可能的加密方式:\n\n")
            
            for i, (method, name, result) in enumerate(results, 1):
                self.detect_output.insert(tk.END, f"{i}. {name} ({method})\n")
                self.detect_output.insert(tk.END, f"   解密结果: {result}\n\n")
                
        self.detect_output.insert(tk.END, "\n" + "=" * 80 + "\n")
        
    def display_detect_error(self, error_msg):
        self.progress.stop()
        self.status_label.config(text="检测失败")
        self.detect_output.insert("1.0", f"检测过程中发生错误: {error_msg}\n")
        
    def clear_detect(self):
        self.detect_input.delete("1.0", tk.END)
        self.detect_output.delete("1.0", tk.END)
        self.status_label.config(text="就绪")
        
    def show_all_algorithms(self):
        self.help_text.delete("1.0", tk.END)
        
        help_content = """
加密工具算法说明
==================

一、Base 编码系列
------------------
Base16: 将二进制数据转换为16进制表示
Base32: 使用32个字符进行编码（A-Z, 2-7）
Base36: 使用0-9和A-Z进行编码
Base58: 去除易混淆字符的Base编码（0, O, I, l等）
Base62: 使用0-9, A-Z, a-z进行编码
Base64: 最常用的Base编码，使用64个字符
Base85: 使用85个字符进行编码，比Base64更紧凑
Base91: 使用91个可打印ASCII字符进行编码
Base92: 使用92个可打印ASCII字符进行编码

二、编码转换
------------------
Hex: 十六进制编码
URL编码: 将特殊字符转换为%XX格式
HTML编码: 将特殊字符转换为HTML实体
Escape编码: 类似于URL编码，用于JavaScript
ASCII编码: 将字符转换为ASCII码
Quoted编码: 使用=XX格式进行编码

三、古典密码
------------------
Caesar密码: 凯撒密码，字母表移位加密（需要移位值）
Vigenère密码: 维吉尼亚密码，使用密钥进行多表替换（需要密钥）
ROT13: 凯撒密码的特例，移位13位
Atbash密码: 希伯来字母表反转密码
Affine密码: 仿射密码，使用线性函数加密（需要a,b参数）
Railfence密码: 栅栏密码，按之字形排列
A1Z26: 将字母转换为数字（A=1, B=2, ..., Z=26）
Playfair密码: 普莱费尔密码，使用5x5矩阵进行双字母替换（需要密钥）

四、现代加密
------------------
AES加密: 高级加密标准，支持128/192/256位密钥（需要密钥）
DES加密: 数据加密标准，使用56位密钥（需要密钥）
3DES加密: 三重DES加密，更安全（需要密钥）
RC4加密: 流密码算法（需要密钥）

五、特殊编码
------------------
Morse密码: 摩尔斯电码，使用点和划表示
Tapcode: 敲击码，用于监狱通信
猪圈密码: 使用几何图形表示字母
Baconian密码: 培根密码，使用A/B两种字母表示

六、其他编码
------------------
XXencode: 类似于Base64的编码方式
UUencode: Unix-to-Unix编码
JSfuck: 仅使用6个字符的JavaScript混淆编码
Brainfuck: 极简主义编程语言编码
Bubble编码: 使用气泡图形表示
AAencode: 使用颜文字进行编码
JJencode: 使用JavaScript语法混淆
PPencode: 使用Perl语法混淆

七、进制转换
------------------
二进制: 0和1表示
八进制: 0-7表示
十进制: 0-9表示
十六进制: 0-9和A-F表示

八、哈希函数
------------------
MD5: 128位哈希值
SHA1: 160位哈希值
SHA256: 256位哈希值
SHA384: 384位哈希值
SHA512: 512位哈希值
RIPEMD160: 160位哈希值

注意: 哈希函数是单向的，只能加密不能解密。
"""
        
        self.help_text.insert("1.0", help_content)
        
    def search_algorithms(self):
        search_term = self.search_var.get().lower().strip()
        
        if not search_term:
            self.show_all_algorithms()
            return
            
        self.help_text.delete("1.0", tk.END)
        
        all_content = """
加密工具算法说明
==================

一、Base 编码系列
------------------
Base16: 将二进制数据转换为16进制表示
Base32: 使用32个字符进行编码（A-Z, 2-7）
Base36: 使用0-9和A-Z进行编码
Base58: 去除易混淆字符的Base编码（0, O, I, l等）
Base62: 使用0-9, A-Z, a-z进行编码
Base64: 最常用的Base编码，使用64个字符
Base85: 使用85个字符进行编码，比Base64更紧凑
Base91: 使用91个可打印ASCII字符进行编码
Base92: 使用92个可打印ASCII字符进行编码

二、编码转换
------------------
Hex: 十六进制编码
URL编码: 将特殊字符转换为%XX格式
HTML编码: 将特殊字符转换为HTML实体
Escape编码: 类似于URL编码，用于JavaScript
ASCII编码: 将字符转换为ASCII码
Quoted编码: 使用=XX格式进行编码

三、古典密码
------------------
Caesar密码: 凯撒密码，字母表移位加密（需要移位值）
Vigenère密码: 维吉尼亚密码，使用密钥进行多表替换（需要密钥）
ROT13: 凯撒密码的特例，移位13位
Atbash密码: 希伯来字母表反转密码
Affine密码: 仿射密码，使用线性函数加密（需要a,b参数）
Railfence密码: 栅栏密码，按之字形排列
A1Z26: 将字母转换为数字（A=1, B=2, ..., Z=26）
Playfair密码: 普莱费尔密码，使用5x5矩阵进行双字母替换（需要密钥）

四、现代加密
------------------
AES加密: 高级加密标准，支持128/192/256位密钥（需要密钥）
DES加密: 数据加密标准，使用56位密钥（需要密钥）
3DES加密: 三重DES加密，更安全（需要密钥）
RC4加密: 流密码算法（需要密钥）

五、特殊编码
------------------
Morse密码: 摩尔斯电码，使用点和划表示
Tapcode: 敲击码，用于监狱通信
猪圈密码: 使用几何图形表示字母
Baconian密码: 培根密码，使用A/B两种字母表示

六、其他编码
------------------
XXencode: 类似于Base64的编码方式
UUencode: Unix-to-Unix编码
JSfuck: 仅使用6个字符的JavaScript混淆编码
Brainfuck: 极简主义编程语言编码
Bubble编码: 使用气泡图形表示
AAencode: 使用颜文字进行编码
JJencode: 使用JavaScript语法混淆
PPencode: 使用Perl语法混淆

七、进制转换
------------------
二进制: 0和1表示
八进制: 0-7表示
十进制: 0-9表示
十六进制: 0-9和A-F表示

八、哈希函数
------------------
MD5: 128位哈希值
SHA1: 160位哈希值
SHA256: 256位哈希值
SHA384: 384位哈希值
SHA512: 512位哈希值
RIPEMD160: 160位哈希值

注意: 哈希函数是单向的，只能加密不能解密。
"""
        
        lines = all_content.split('\n')
        filtered_lines = []
        
        for line in lines:
            if search_term in line.lower():
                filtered_lines.append(line)
                
        if filtered_lines:
            self.help_text.insert("1.0", "搜索结果:\n")
            self.help_text.insert(tk.END, "=" * 80 + "\n\n")
            for line in filtered_lines:
                self.help_text.insert(tk.END, line + "\n")
        else:
            self.help_text.insert("1.0", f"未找到包含 '{search_term}' 的算法。\n")
            self.help_text.insert(tk.END, "\n请尝试其他关键词。")
    
    def copy_detect_result(self):
        """复制检测结果"""
        result = self.detect_output.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("成功", "结果已复制到剪贴板！")


def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
