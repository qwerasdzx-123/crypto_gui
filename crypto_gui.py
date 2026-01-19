#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font, filedialog
from crypto_tool import CryptoTool
import threading
import webbrowser


class ThemeManager:
    def __init__(self):
        self.current_theme = 'light'
        
        self.themes = {
            'light': {
                'background': '#f5f5f7',
                'surface': '#ffffff',
                'surface_hover': '#fafafa',
                'text': '#1d1d1f',
                'text_secondary': '#86868b',
                'text_disabled': '#c7c7cc',
                'primary': '#007aff',
                'primary_hover': '#0051d5',
                'primary_light': '#e3f2fd',
                'success': '#34c759',
                'warning': '#ff9500',
                'error': '#ff3b30',
                'border': '#d2d2d7',
                'border_light': '#e5e5ea',
                'divider': '#e5e5ea',
                'shadow': 'rgba(0, 0, 0, 0.08)',
                'card': '#ffffff',
                'card_border': '#e0e0e0',
                'input_bg': '#ffffff',
                'input_border': '#d2d2d7',
                'input_focus': '#007aff',
                'scrollbar': '#c7c7cc',
                'scrollbar_hover': '#86868b'
            },
            'dark': {
                'background': '#1c1c1e',
                'surface': '#2c2c2e',
                'surface_hover': '#3a3a3c',
                'text': '#f5f5f7',
                'text_secondary': '#98989d',
                'text_disabled': '#48484a',
                'primary': '#0a84ff',
                'primary_hover': '#0051d5',
                'primary_light': '#1c1c1e',
                'success': '#30d158',
                'warning': '#ff9f0a',
                'error': '#ff453a',
                'border': '#48484a',
                'border_light': '#3a3a3c',
                'divider': '#3a3a3c',
                'shadow': 'rgba(0, 0, 0, 0.3)',
                'card': '#2c2c2e',
                'card_border': '#3a3a3c',
                'input_bg': '#1c1c1e',
                'input_border': '#48484a',
                'input_focus': '#0a84ff',
                'scrollbar': '#48484a',
                'scrollbar_hover': '#636366'
            }
        }
        
        self.fonts = {
            'title': ('Segoe UI', 22, 'bold'),
            'heading': ('Segoe UI', 15, 'bold'),
            'subheading': ('Segoe UI', 13, 'bold'),
            'body': ('Segoe UI', 12),
            'body_bold': ('Segoe UI', 12, 'bold'),
            'small': ('Segoe UI', 10),
            'code': ('Consolas', 11)
        }
    
    def get_color(self, name):
        return self.themes[self.current_theme][name]
    
    def get_font(self, name):
        return self.fonts[name]
    
    def toggle_theme(self):
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        return self.current_theme


class ErrorDialog:
    def __init__(self, parent, title, message, suggestion=None, error_type='error'):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("500x350")
        self.dialog.resizable(False, False)
        
        self.theme_manager = parent.theme_manager if hasattr(parent, 'theme_manager') else ThemeManager()
        
        bg = self.theme_manager.get_color('background')
        card = self.theme_manager.get_color('card')
        text = self.theme_manager.get_color('text')
        text_secondary = self.theme_manager.get_color('text_secondary')
        error_color = self.theme_manager.get_color('error')
        
        self.dialog.configure(bg=bg)
        
        main_frame = tk.Frame(self.dialog, bg=bg)
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)
        
        icon_frame = tk.Frame(main_frame, bg=card)
        icon_frame.pack(pady=(0, 15))
        
        icon_text = '❌' if error_type == 'error' else '⚠️' if error_type == 'warning' else '✅'
        tk.Label(icon_frame, text=icon_text, font=('Arial', 48), bg=card).pack()
        
        title_label = tk.Label(
            main_frame,
            text=title,
            font=self.theme_manager.get_font('heading'),
            fg=text,
            bg=bg
        )
        title_label.pack(pady=(0, 15))
        
        msg_frame = tk.Frame(main_frame, bg=card)
        msg_frame.pack(fill='x', pady=(0, 10))
        
        msg_label = tk.Label(
            msg_frame,
            text=message,
            font=self.theme_manager.get_font('body'),
            fg=text,
            bg=card,
            wraplength=440,
            justify='left'
        )
        msg_label.pack(anchor='w', padx=10, pady=10)
        
        if suggestion:
            suggestion_frame = tk.Frame(main_frame, bg=card)
            suggestion_frame.pack(fill='x', pady=(0, 20))
            
            tk.Label(
                suggestion_frame,
                text="💡 建议:",
                font=self.theme_manager.get_font('body_bold'),
                fg=text,
                bg=card
            ).pack(anchor='w', padx=10, pady=(10, 5))
            
            tk.Label(
                suggestion_frame,
                text=suggestion,
                font=self.theme_manager.get_font('body'),
                fg=text_secondary,
                bg=card,
                wraplength=440,
                justify='left'
            ).pack(anchor='w', padx=10, pady=(0, 10))
        
        button_frame = tk.Frame(main_frame, bg=bg)
        button_frame.pack(fill='x')
        
        tk.Button(
            button_frame,
            text="确定",
            command=self.dialog.destroy,
            font=self.theme_manager.get_font('body_bold'),
            bg=self.theme_manager.get_color('primary'),
            fg='white',
            relief='flat',
            padx=30,
            pady=10,
            cursor='hand2'
        ).pack(side='right')
        
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.focus_set()


class ModernButton(tk.Canvas):
    def __init__(self, parent, text, command=None, style='primary', **kwargs):
        self.theme_manager = kwargs.pop('theme_manager', None)
        super().__init__(parent, **kwargs)
        
        self.text = text
        self.command = command
        self.style = style
        self.hover = False
        self.pressed = False
        
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.bind('<Button-1>', self.on_press)
        self.bind('<ButtonRelease-1>', self.on_release)
        
        self.draw()
    
    def draw(self):
        self.delete('all')
        
        if self.theme_manager:
            if self.style == 'primary':
                bg = self.theme_manager.get_color('primary_hover') if self.hover else self.theme_manager.get_color('primary')
                fg = '#ffffff'
            elif self.style == 'secondary':
                bg = self.theme_manager.get_color('surface_hover') if self.hover else self.theme_manager.get_color('surface')
                fg = self.theme_manager.get_color('text')
            elif self.style == 'ghost':
                bg = self.theme_manager.get_color('primary_light') if self.hover else 'transparent'
                fg = self.theme_manager.get_color('primary')
            else:
                bg = self.theme_manager.get_color('surface')
                fg = self.theme_manager.get_color('text')
        else:
            bg = '#007aff' if self.style == 'primary' else '#ffffff'
            fg = '#ffffff' if self.style == 'primary' else '#1d1d1f'
        
        if self.style != 'ghost':
            self.configure(bg=bg, highlightthickness=0)
            self.create_rectangle(0, 0, self.winfo_width(), self.winfo_height(), 
                                  fill=bg, outline='', tags='bg')
        
        font = self.theme_manager.get_font('body') if self.theme_manager else ('Arial', 12)
        self.create_text(self.winfo_width() / 2, self.winfo_height() / 2, 
                        text=self.text, fill=fg, font=font, tags='text')
    
    def on_enter(self, event):
        self.hover = True
        self.draw()
    
    def on_leave(self, event):
        self.hover = False
        self.draw()
    
    def on_press(self, event):
        self.pressed = True
        self.draw()
    
    def on_release(self, event):
        self.pressed = False
        self.draw()
        if self.command:
            self.command()


class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("加密工具 - Crypto Tool")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 750)
        
        self.theme_manager = ThemeManager()
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
            "Beaufort密码": "beaufort",
            "Porta密码": "porta",
            "Autokey密码": "autokey",
            "Bifid密码": "bifid",
            "Four-Square密码": "four",
            "Gronsfeld密码": "gronsfeld",
            "Keyword密码": "keyword",
            "Running Key密码": "runkey",
            "Simple密码": "simple",
            "Columnar密码": "columnar",
            "ADFGX密码": "adfgx",
            "ADFGVX密码": "adfgvx",
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
            "Brainfuck": "brainfuck",
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
            'railfence': {'type': 'integer', 'label': '栅栏数', 'default': 3, 'min': 2, 'max': 10},
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
            'aes': {'type': 'aes', 'label': '密钥', 'default': '', 'key_length': [16, 24, 32], 'mode': 'ECB', 'padding': 'PKCS7'},
            'des': {'type': 'des', 'label': '密钥', 'default': '', 'key_length': 8, 'mode': 'ECB', 'padding': 'PKCS7'},
            '3des': {'type': '3des', 'label': '密钥', 'default': '', 'key_length': [16, 24], 'mode': 'ECB', 'padding': 'PKCS7'},
            'rc4': {'type': 'text', 'label': '密钥', 'default': ''}
        }
        
        self.setup_ui()
        self.apply_theme()
        
    def setup_ui(self):
        self.main_container = tk.Frame(self.root)
        self.main_container.pack(fill='both', expand=True)
        
        self.setup_header()
        self.setup_content()
        
    def setup_header(self):
        self.header = tk.Frame(self.main_container, height=60)
        self.header.pack(fill='x', side='top')
        self.header.pack_propagate(False)
        
        self.header_left = tk.Frame(self.header)
        self.header_left.pack(side='left', padx=30, pady=15)
        
        self.title_label = tk.Label(
            self.header_left,
            text="🔐 Crypto Tool",
            font=self.theme_manager.get_font('title'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('background')
        )
        self.title_label.pack(side='left')
        
        self.header_right = tk.Frame(self.header)
        self.header_right.pack(side='right', padx=30, pady=15)
        
        self.github_button = tk.Button(
            self.header_right,
            text="📦 GitHub",
            command=self.open_github,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2'
        )
        self.github_button.pack(side='left', padx=(0, 10))
        
        self.theme_button = tk.Button(
            self.header_right,
            text="🌙",
            command=self.toggle_theme,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2'
        )
        self.theme_button.pack(side='left')
        
    def setup_content(self):
        self.content_frame = tk.Frame(self.main_container)
        self.content_frame.pack(fill='both', expand=True, padx=30, pady=(0, 30))
        
        self.setup_tabs()
        
    def setup_tabs(self):
        self.tab_frame = tk.Frame(self.content_frame, height=50)
        self.tab_frame.pack(fill='x', side='top')
        self.tab_frame.pack_propagate(False)
        
        self.tabs = []
        self.tab_contents = []
        
        tab_names = ['加解密', '自动检测', '算法说明']
        for i, name in enumerate(tab_names):
            tab = tk.Button(
                self.tab_frame,
                text=name,
                command=lambda idx=i: self.switch_tab(idx),
                font=self.theme_manager.get_font('body_bold'),
                bg=self.theme_manager.get_color('background'),
                fg=self.theme_manager.get_color('text_secondary'),
                relief='flat',
                padx=20,
                pady=12,
                cursor='hand2'
            )
            tab.pack(side='left', padx=(0, 5))
            self.tabs.append(tab)
            
            content = tk.Frame(self.content_frame)
            content.pack(fill='both', expand=True)
            content.pack_forget()
            self.tab_contents.append(content)
        
        self.current_tab = 0
        self.setup_encrypt_tab()
        self.setup_detect_tab()
        self.setup_help_tab()
        
        self.switch_tab(0)
        
    def switch_tab(self, index):
        for i, tab in enumerate(self.tabs):
            if i == index:
                tab.config(
                    fg=self.theme_manager.get_color('primary'),
                    bg=self.theme_manager.get_color('background')
                )
                self.tab_contents[i].pack(fill='both', expand=True)
            else:
                tab.config(
                    fg=self.theme_manager.get_color('text_secondary'),
                    bg=self.theme_manager.get_color('background')
                )
                self.tab_contents[i].pack_forget()
        
        self.current_tab = index
        
    def setup_encrypt_tab(self):
        tab = self.tab_contents[0]
        
        main_frame = tk.Frame(tab, bg=self.theme_manager.get_color('background'))
        main_frame.pack(fill='both', expand=True)
        
        top_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        top_section.pack(fill='x', pady=(0, 20))
        
        card = tk.Frame(
            top_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        card.pack(fill='x', padx=0, pady=0)
        
        inner_frame = tk.Frame(card, bg=self.theme_manager.get_color('card'))
        inner_frame.pack(fill='x', padx=20, pady=20)
        
        tk.Label(
            inner_frame,
            text="选择加密/解密方式",
            font=self.theme_manager.get_font('heading'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        ).pack(anchor='w', pady=(0, 10))
        
        self.method_var = tk.StringVar()
        self.method_combo = ttk.Combobox(
            inner_frame,
            textvariable=self.method_var,
            state='readonly',
            font=self.theme_manager.get_font('body'),
            width=20
        )
        self.method_combo.bind('<<ComboboxSelected>>', self.on_method_changed)
        
        self.load_methods()
        
        options_frame = tk.Frame(inner_frame, bg=self.theme_manager.get_color('card'))
        options_frame.pack(fill='x', pady=(0, 0))
        
        method_row = tk.Frame(options_frame, bg=self.theme_manager.get_color('card'))
        method_row.pack(fill='x', pady=(0, 10))
        
        method_label = tk.Label(
            method_row,
            text="方式",
            font=self.theme_manager.get_font('body'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        )
        method_label.pack(side='left', padx=(0, 5))
        self.method_combo.pack(side='left', padx=(0, 20))
        
        key_row = tk.Frame(options_frame, bg=self.theme_manager.get_color('card'))
        key_row.pack(fill='x')
        
        self.key_label = tk.Label(
            key_row,
            text="🔑",
            font=self.theme_manager.get_font('body_bold'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        )
        self.key_label.pack(side='left', padx=(0, 5))
        
        self.key_entry = tk.Entry(
            key_row,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='solid',
            bd=1,
            highlightbackground=self.theme_manager.get_color('primary'),
            highlightcolor=self.theme_manager.get_color('primary'),
            highlightthickness=1,
            width=15
        )
        self.key_entry.pack(side='left', padx=(0, 10))
        
        self.key_info_label = tk.Label(
            key_row,
            text="",
            font=self.theme_manager.get_font('small'),
            fg=self.theme_manager.get_color('text_secondary'),
            bg=self.theme_manager.get_color('card')
        )
        self.key_info_label.pack(side='left', padx=(0, 10))
        
        self.iv_label = tk.Label(
            key_row,
            text="偏移量",
            font=self.theme_manager.get_font('body'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        )
        
        self.iv_entry = tk.Entry(
            key_row,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='solid',
            bd=1,
            highlightbackground=self.theme_manager.get_color('primary'),
            highlightcolor=self.theme_manager.get_color('primary'),
            highlightthickness=1,
            width=20
        )
        
        self.mode_label = tk.Label(
            key_row,
            text="模式",
            font=self.theme_manager.get_font('body'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        )
        
        self.mode_var = tk.StringVar(value='ECB')
        self.mode_combo = ttk.Combobox(
            key_row,
            textvariable=self.mode_var,
            values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM'],
            state='readonly',
            font=self.theme_manager.get_font('body'),
            width=8
        )
        
        self.padding_label = tk.Label(
            key_row,
            text="填充",
            font=self.theme_manager.get_font('body'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        )
        
        self.padding_var = tk.StringVar(value='PKCS7')
        self.padding_combo = ttk.Combobox(
            key_row,
            textvariable=self.padding_var,
            values=['PKCS7', 'ISO7816', 'ISO10126', 'X923', 'Zero'],
            state='readonly',
            font=self.theme_manager.get_font('body'),
            width=8
        )
        
        self.output_format_label = tk.Label(
            key_row,
            text="编码",
            font=self.theme_manager.get_font('body'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        )
        
        self.output_format_var = tk.StringVar(value='Base64')
        self.output_format_combo = ttk.Combobox(
            key_row,
            textvariable=self.output_format_var,
            values=['Base64', 'Hex'],
            state='readonly',
            font=self.theme_manager.get_font('body'),
            width=8
        )
        
        middle_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        middle_section.pack(fill='both', expand=True)
        
        input_card = tk.Frame(
            middle_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        input_card.pack(fill='both', expand=True, pady=(0, 15))
        
        input_inner = tk.Frame(input_card, bg=self.theme_manager.get_color('card'))
        input_inner.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(
            input_inner,
            text="输入文本",
            font=self.theme_manager.get_font('heading'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        ).pack(anchor='w', pady=(0, 10))
        
        self.input_text = scrolledtext.ScrolledText(
            input_inner,
            height=8,
            wrap=tk.WORD,
            font=self.theme_manager.get_font('code'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='flat',
            padx=15,
            pady=15
        )
        self.input_text.pack(fill='both', expand=True)
        
        button_frame = tk.Frame(middle_section, bg=self.theme_manager.get_color('background'))
        button_frame.pack(fill='x', pady=(0, 15))
        
        self.encrypt_button = tk.Button(
            button_frame,
            text="🔒 加密",
            command=self.encrypt_text,
            font=self.theme_manager.get_font('body_bold'),
            bg=self.theme_manager.get_color('primary'),
            fg='white',
            relief='flat',
            padx=25,
            pady=10,
            cursor='hand2'
        )
        self.encrypt_button.pack(side='left', padx=(0, 10))
        
        self.decrypt_button = tk.Button(
            button_frame,
            text="🔓 解密",
            command=self.decrypt_text,
            font=self.theme_manager.get_font('body_bold'),
            bg=self.theme_manager.get_color('primary'),
            fg='white',
            relief='flat',
            padx=25,
            pady=10,
            cursor='hand2'
        )
        self.decrypt_button.pack(side='left', padx=(0, 10))
        
        tk.Button(
            button_frame,
            text="🗑️ 清空",
            command=self.clear_encrypt,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left', padx=(0, 10))
        
        tk.Button(
            button_frame,
            text="📂 导入文件",
            command=self.import_file,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left', padx=(0, 10))
        
        tk.Button(
            button_frame,
            text="💾 保存结果",
            command=self.export_file,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='right', padx=(10, 0))
        
        tk.Button(
            button_frame,
            text="📋 复制结果",
            command=self.copy_result,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='right')
        
        output_card = tk.Frame(
            middle_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        output_card.pack(fill='both', expand=True)
        
        output_inner = tk.Frame(output_card, bg=self.theme_manager.get_color('card'))
        output_inner.pack(fill='both', expand=True, padx=20, pady=20)
        
        self.status_label = tk.Label(
            output_inner,
            text="就绪",
            font=self.theme_manager.get_font('small'),
            fg=self.theme_manager.get_color('text_secondary'),
            bg=self.theme_manager.get_color('card')
        )
        self.status_label.pack(anchor='w', pady=(0, 10))
        
        tk.Label(
            output_inner,
            text="结果",
            font=self.theme_manager.get_font('heading'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        ).pack(anchor='w', pady=(0, 10))
        
        self.output_text = scrolledtext.ScrolledText(
            output_inner,
            height=8,
            wrap=tk.WORD,
            font=self.theme_manager.get_font('code'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='flat',
            padx=15,
            pady=15
        )
        self.output_text.pack(fill='both', expand=True)
        
    def setup_detect_tab(self):
        tab = self.tab_contents[1]
        
        main_frame = tk.Frame(tab, bg=self.theme_manager.get_color('background'))
        main_frame.pack(fill='both', expand=True)
        
        top_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        top_section.pack(fill='x', pady=(0, 15))
        
        card = tk.Frame(
            top_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        card.pack(fill='x', padx=0, pady=0)
        
        inner_frame = tk.Frame(card, bg=self.theme_manager.get_color('card'))
        inner_frame.pack(fill='x', padx=20, pady=20)
        
        tk.Label(
            inner_frame,
            text="输入密文",
            font=self.theme_manager.get_font('heading'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        ).pack(anchor='w', pady=(0, 10))
        
        self.detect_input = scrolledtext.ScrolledText(
            inner_frame,
            height=5,
            wrap=tk.WORD,
            font=self.theme_manager.get_font('code'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='flat',
            padx=15,
            pady=15
        )
        self.detect_input.pack(fill='both', expand=True)
        
        button_frame = tk.Frame(inner_frame, bg=self.theme_manager.get_color('card'))
        button_frame.pack(fill='x', pady=(15, 0))
        
        tk.Button(
            button_frame,
            text="🔍 自动检测加密方式",
            command=self.detect_encryption,
            font=self.theme_manager.get_font('body_bold'),
            bg=self.theme_manager.get_color('primary'),
            fg='white',
            relief='flat',
            padx=25,
            pady=10,
            cursor='hand2'
        ).pack(side='left', padx=(0, 10))
        
        tk.Button(
            button_frame,
            text="🗑️ 清空",
            command=self.clear_detect,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left')
        
        middle_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        middle_section.pack(fill='x', pady=(0, 15))
        
        key_card = tk.Frame(
            middle_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        key_card.pack(fill='x', padx=0, pady=0)
        
        key_inner = tk.Frame(key_card, bg=self.theme_manager.get_color('card'))
        key_inner.pack(fill='x', padx=20, pady=20)
        
        tk.Label(
            key_inner,
            text="🔑 密钥输入（可选）",
            font=self.theme_manager.get_font('heading'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        ).pack(anchor='w', pady=(0, 10))
        
        self.detect_key_entry = tk.Entry(
            key_inner,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='solid',
            bd=1,
            highlightbackground=self.theme_manager.get_color('primary'),
            highlightcolor=self.theme_manager.get_color('primary'),
            highlightthickness=1,
            width=25
        )
        self.detect_key_entry.pack(anchor='w', pady=(0, 5))
        
        tk.Label(
            key_inner,
            text="💡 提示: 如果填写了密钥，将尝试所有需要密钥的解密方式；如果不填写，只尝试不需要密钥的解密方式。",
            font=self.theme_manager.get_font('small'),
            fg=self.theme_manager.get_color('text_secondary'),
            bg=self.theme_manager.get_color('card'),
            wraplength=800
        ).pack(anchor='w', pady=(5, 0))
        
        bottom_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        bottom_section.pack(fill='both', expand=True)
        
        output_card = tk.Frame(
            bottom_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        output_card.pack(fill='both', expand=True, padx=0, pady=0)
        
        output_inner = tk.Frame(output_card, bg=self.theme_manager.get_color('card'))
        output_inner.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(
            output_inner,
            text="检测结果",
            font=self.theme_manager.get_font('heading'),
            fg=self.theme_manager.get_color('text'),
            bg=self.theme_manager.get_color('card')
        ).pack(anchor='w', pady=(0, 10))
        
        self.detect_output = scrolledtext.ScrolledText(
            output_inner,
            height=12,
            wrap=tk.WORD,
            font=self.theme_manager.get_font('code'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='flat',
            padx=15,
            pady=15
        )
        self.detect_output.pack(fill='both', expand=True)
        
        output_button_frame = tk.Frame(output_inner, bg=self.theme_manager.get_color('card'))
        output_button_frame.pack(fill='x', pady=(15, 0))
        
        tk.Button(
            output_button_frame,
            text="📋 复制结果",
            command=self.copy_detect_result,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left')
        
        progress_frame = tk.Frame(output_inner, bg=self.theme_manager.get_color('card'))
        progress_frame.pack(fill='x', pady=(15, 0))
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.pack(fill='x')
        
        self.status_label = tk.Label(
            progress_frame,
            text="就绪",
            font=self.theme_manager.get_font('small'),
            fg=self.theme_manager.get_color('text_secondary'),
            bg=self.theme_manager.get_color('card')
        )
        self.status_label.pack(pady=(8, 0))
        
    def setup_help_tab(self):
        tab = self.tab_contents[2]
        
        main_frame = tk.Frame(tab, bg=self.theme_manager.get_color('background'))
        main_frame.pack(fill='both', expand=True)
        
        top_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        top_section.pack(fill='x', pady=(0, 20))
        
        card = tk.Frame(
            top_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        card.pack(fill='x', padx=0, pady=0)
        
        inner_frame = tk.Frame(card, bg=self.theme_manager.get_color('card'))
        inner_frame.pack(fill='x', padx=20, pady=20)
        
        search_frame = tk.Frame(inner_frame, bg=self.theme_manager.get_color('card'))
        search_frame.pack(fill='x')
        
        tk.Label(
            search_frame,
            text="🔍",
            font=self.theme_manager.get_font('body'),
            fg=self.theme_manager.get_color('text_secondary'),
            bg=self.theme_manager.get_color('card')
        ).pack(side='left', padx=(0, 10))
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='solid',
            bd=1
        )
        search_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        tk.Button(
            search_frame,
            text="搜索",
            command=self.search_algorithms,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('primary'),
            fg='white',
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        ).pack(side='left', padx=(0, 10))
        
        tk.Button(
            search_frame,
            text="显示全部",
            command=self.show_all_algorithms,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('surface'),
            fg=self.theme_manager.get_color('text'),
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        ).pack(side='left')
        
        bottom_section = tk.Frame(main_frame, bg=self.theme_manager.get_color('background'))
        bottom_section.pack(fill='both', expand=True)
        
        help_card = tk.Frame(
            bottom_section,
            bg=self.theme_manager.get_color('card'),
            relief='flat',
            bd=1
        )
        help_card.pack(fill='both', expand=True)
        
        help_inner = tk.Frame(help_card, bg=self.theme_manager.get_color('card'))
        help_inner.pack(fill='both', expand=True, padx=20, pady=20)
        
        self.help_text = scrolledtext.ScrolledText(
            help_inner,
            wrap=tk.WORD,
            font=self.theme_manager.get_font('body'),
            bg=self.theme_manager.get_color('input_bg'),
            fg=self.theme_manager.get_color('text'),
            insertbackground=self.theme_manager.get_color('primary'),
            relief='flat',
            padx=20,
            pady=20
        )
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
            "Beaufort密码", "Porta密码", "Autokey密码", "Bifid密码",
            "Four-Square密码", "Gronsfeld密码", "Keyword密码", "Running Key密码",
            "Simple密码", "Columnar密码", "ADFGX密码", "ADFGVX密码",
            "现代加密",
            "AES加密", "DES加密", "3DES加密", "RC4加密",
            "特殊编码",
            "Morse密码", "Tapcode", "猪圈密码", "Baconian密码",
            "其他编码",
            "XXencode", "UUencode", "Brainfuck",
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
            req = self.key_requirements[method]
            self.key_label.config(text=f"🔑 {req['label']}:")
            
            if req['type'] == 'shift':
                self.key_info_label.config(text="请输入移位值（整数）")
                self.hide_advanced_options()
            elif req['type'] == 'affine':
                self.key_info_label.config(text="请输入a,b参数（例如：5,8）")
                self.hide_advanced_options()
            elif req['type'] == 'integer':
                min_val = req.get('min', 2)
                max_val = req.get('max', 10)
                self.key_info_label.config(text=f"请输入{req['label']}（{min_val}-{max_val}）")
                self.hide_advanced_options()
            elif req['type'] in ['aes', 'des', '3des']:
                if req['type'] == 'aes':
                    self.key_info_label.config(text="请输入密钥（16/24/32字节）")
                elif req['type'] == 'des':
                    self.key_info_label.config(text="请输入密钥（8字节）")
                elif req['type'] == '3des':
                    self.key_info_label.config(text="请输入密钥（16/24字节）")
                self.show_advanced_options()
            else:
                self.key_info_label.config(text="请输入密钥文本")
                self.hide_advanced_options()
        else:
            self.key_label.config(text="🔑 密钥 / 偏移位")
            self.key_info_label.config(text="此加密方式不需要密钥或偏移位")
            self.key_entry.delete(0, tk.END)
            self.hide_advanced_options()
        
        hash_methods = ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'ripemd160']
        if method in hash_methods:
            self.decrypt_button.config(state='disabled', bg=self.theme_manager.get_color('text_disabled'))
        else:
            self.decrypt_button.config(state='normal', bg=self.theme_manager.get_color('primary'))
    
    def show_advanced_options(self):
        self.iv_label.pack(side='left', padx=(0, 5))
        self.iv_entry.pack(side='left', padx=(0, 10))
        self.mode_label.pack(side='left', padx=(0, 5))
        self.mode_combo.pack(side='left', padx=(0, 10))
        self.padding_label.pack(side='left', padx=(0, 5))
        self.padding_combo.pack(side='left', padx=(0, 10))
        self.output_format_label.pack(side='left', padx=(0, 5))
        self.output_format_combo.pack(side='left')
    
    def hide_advanced_options(self):
        self.iv_label.pack_forget()
        self.iv_entry.pack_forget()
        self.mode_label.pack_forget()
        self.mode_combo.pack_forget()
        self.padding_label.pack_forget()
        self.padding_combo.pack_forget()
        self.output_format_label.pack_forget()
        self.output_format_combo.pack_forget()
            
    def get_key_params(self, method):
        if method not in self.key_requirements:
            return {}
        
        req = self.key_requirements[method]
        key_text = self.key_entry.get().strip()
        iv_text = self.iv_entry.get().strip() if hasattr(self, 'iv_entry') else ''
        mode = self.mode_var.get() if hasattr(self, 'mode_var') else 'ECB'
        padding = self.padding_var.get() if hasattr(self, 'padding_var') else 'PKCS7'
        output_format = self.output_format_var.get().lower() if hasattr(self, 'output_format_var') else 'base64'
        
        params = {}
        
        if req['type'] == 'shift':
            try:
                params['shift'] = int(key_text)
            except ValueError:
                params['shift'] = req['default']
        elif req['type'] == 'integer':
            try:
                value = int(key_text)
                min_val = req.get('min', 2)
                max_val = req.get('max', 10)
                if value < min_val or value > max_val:
                    value = req['default']
                params['rails'] = value
            except ValueError:
                params['rails'] = req['default']
        elif req['type'] == 'affine':
            parts = key_text.split(',')
            if len(parts) == 2:
                try:
                    params['a'] = int(parts[0])
                    params['b'] = int(parts[1])
                except ValueError:
                    pass
            params['a'] = 5
            params['b'] = 8
        else:
            params['key'] = key_text
        
        if method in ['aes', 'des', '3des']:
            if iv_text:
                params['iv'] = iv_text
            params['mode'] = mode
            params['padding'] = padding
            params['output_format'] = output_format
        
        return params
    
    def encrypt_text(self):
        method_display = self.method_var.get()
        method = self.method_mapping.get(method_display)
        
        if not method:
            messagebox.showerror("错误", "请选择一个具体的加密方式！")
            return
        
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("警告", "请输入要加密的文本！")
            return
        
        try:
            self.status_label.config(text="正在加密...", fg=self.theme_manager.get_color('text_secondary'))
            self.root.update()
            
            params = self.get_key_params(method)
            result = self.tool.encrypt(method, text, **params)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.status_label.config(text="✅ 加密成功", fg=self.theme_manager.get_color('success'))
        except ValueError as e:
            ErrorDialog(self.root, "加密参数错误", str(e), 
                      "请检查密钥、偏移量等参数是否正确。", 'warning')
            self.status_label.config(text="❌ 加密失败", fg=self.theme_manager.get_color('error'))
        except Exception as e:
            ErrorDialog(self.root, "加密失败", str(e), 
                      "请检查输入文本和加密方式是否正确，或尝试其他加密方式。")
            self.status_label.config(text="❌ 加密失败", fg=self.theme_manager.get_color('error'))
    
    def decrypt_text(self):
        method_display = self.method_var.get()
        method = self.method_mapping.get(method_display)
        
        if not method:
            messagebox.showerror("错误", "请选择一个具体的解密方式！")
            return
        
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("警告", "请输入要解密的文本！")
            return
        
        try:
            self.status_label.config(text="正在解密...", fg=self.theme_manager.get_color('text_secondary'))
            self.root.update()
            
            params = self.get_key_params(method)
            result = self.tool.decrypt(method, text, **params)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.status_label.config(text="✅ 解密成功", fg=self.theme_manager.get_color('success'))
        except ValueError as e:
            ErrorDialog(self.root, "解密参数错误", str(e), 
                      "请检查密钥、偏移量等参数是否正确。", 'warning')
            self.status_label.config(text="❌ 解密失败", fg=self.theme_manager.get_color('error'))
        except Exception as e:
            ErrorDialog(self.root, "解密失败", str(e), 
                      "请检查密文和密钥是否正确，或尝试其他解密方式。")
            self.status_label.config(text="❌ 解密失败", fg=self.theme_manager.get_color('error'))
    
    def clear_encrypt(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
    
    def import_file(self):
        from tkinter import filedialog
        
        filetypes = [
            ('文本文件', '*.txt'),
            ('所有文件', '*.*')
        ]
        filename = filedialog.askopenfilename(
            title="选择要导入的文件",
            filetypes=filetypes
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert("1.0", content)
                messagebox.showinfo("成功", f"已成功导入文件：{filename}")
            except UnicodeDecodeError:
                try:
                    with open(filename, 'r', encoding='gbk') as f:
                        content = f.read()
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", content)
                    messagebox.showinfo("成功", f"已成功导入文件（GBK编码）：{filename}")
                except Exception as e:
                    ErrorDialog(self.root, "无法读取文件", str(e), 
                              "请确保文件格式正确，或尝试使用其他编码打开文件。")
            except Exception as e:
                ErrorDialog(self.root, "导入文件失败", str(e), 
                              "请检查文件是否存在，或尝试其他文件。")
    
    def export_file(self):
        from tkinter import filedialog
        
        result = self.output_text.get("1.0", tk.END).strip()
        if not result:
            messagebox.showwarning("警告", "没有可保存的内容！")
            return
        
        filetypes = [
            ('文本文件', '*.txt'),
            ('所有文件', '*.*')
        ]
        filename = filedialog.asksaveasfilename(
            title="保存结果",
            defaultextension=".txt",
            filetypes=filetypes
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(result)
                messagebox.showinfo("成功", f"已成功保存到文件：{filename}")
            except Exception as e:
                ErrorDialog(self.root, "保存文件失败", str(e), 
                              "请检查是否有写入权限，或尝试保存到其他位置。")
    
    def copy_result(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("成功", "结果已复制到剪贴板！")
        else:
            messagebox.showwarning("警告", "没有可复制的内容！")
    
    def detect_encryption(self):
        ciphertext = self.detect_input.get("1.0", tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("警告", "请输入要检测的密文！")
            return
        
        key = self.detect_key_entry.get().strip()
        
        def detect_thread():
            try:
                self.root.after(0, lambda: self.progress.start(10))
                self.root.after(0, lambda: self.status_label.config(text="正在检测..."))
                
                results = self.tool.auto_detect(ciphertext, key)
                
                self.root.after(0, lambda: self.progress.stop())
                
                if results:
                    output = "检测到以下可能的加密方式:\n\n"
                    for i, (method, name, result) in enumerate(results, 1):
                        output += f"{i}. {name}\n"
                        output += f"   解密结果: {result[:100]}{'...' if len(result) > 100 else ''}\n\n"
                    
                    self.root.after(0, lambda: self.detect_output.delete("1.0", tk.END))
                    self.root.after(0, lambda: self.detect_output.insert("1.0", output))
                    self.root.after(0, lambda: self.status_label.config(text=f"检测完成，找到 {len(results)} 种可能"))
                else:
                    self.root.after(0, lambda: self.detect_output.delete("1.0", tk.END))
                    self.root.after(0, lambda: self.detect_output.insert("1.0", "未检测到已知的加密方式"))
                    self.root.after(0, lambda: self.status_label.config(text="检测完成，未找到匹配"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: self.status_label.config(text="检测失败"))
                self.root.after(0, lambda: messagebox.showerror("错误", f"检测失败: {str(e)}"))
        
        thread = threading.Thread(target=detect_thread)
        thread.daemon = True
        thread.start()
    
    def clear_detect(self):
        self.detect_input.delete("1.0", tk.END)
        self.detect_output.delete("1.0", tk.END)
        self.detect_key_entry.delete(0, tk.END)
    
    def copy_detect_result(self):
        result = self.detect_output.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("成功", "结果已复制到剪贴板！")
        else:
            messagebox.showwarning("警告", "没有可复制的内容！")
    
    def search_algorithms(self):
        query = self.search_var.get().strip().lower()
        if not query:
            self.show_all_algorithms()
            return
        
        self.help_text.delete("1.0", tk.END)
        
        algorithm_info = self.tool.get_algorithm_info()
        
        found = False
        for name, info in algorithm_info.items():
            if query in name.lower() or query in info.lower():
                self.help_text.insert(tk.END, f"【{name}】\n{info}\n\n")
                found = True
        
        if not found:
            self.help_text.insert(tk.END, f"未找到与 '{query}' 相关的算法。")
    
    def show_all_algorithms(self):
        self.help_text.delete("1.0", tk.END)
        
        algorithm_info = self.tool.get_algorithm_info()
        
        categories = {
            'Base 编码': ['Base16', 'Base32', 'Base36', 'Base58', 'Base62', 'Base64', 'Base85', 'Base91', 'Base92'],
            '编码转换': ['Hex', 'URL编码', 'HTML编码', 'Escape编码', 'ASCII编码', 'Quoted编码'],
            '古典密码': ['Caesar密码', 'Vigenère密码', 'ROT13', 'Atbash密码', 'Affine密码', 'Railfence密码', 'A1Z26', 'Playfair密码', 
                        'Beaufort密码', 'Porta密码', 'Autokey密码', 'Bifid密码', 'Four-Square密码', 'Gronsfeld密码', 
                        'Keyword密码', 'Running Key密码', 'Simple密码', 'Columnar密码', 'ADFGX密码', 'ADFGVX密码'],
            '现代加密': ['AES加密', 'DES加密', '3DES加密', 'RC4加密'],
            '特殊编码': ['Morse密码', 'Tapcode', '猪圈密码', 'Baconian密码'],
            '其他编码': ['XXencode', 'UUencode', 'Brainfuck'],
            '进制转换': ['二进制', '八进制', '十进制', '十六进制'],
            '哈希函数': ['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'RIPEMD160']
        }
        
        for category, algorithms in categories.items():
            self.help_text.insert(tk.END, f"\n{'='*50}\n")
            self.help_text.insert(tk.END, f"【{category}】\n")
            self.help_text.insert(tk.END, f"{'='*50}\n\n")
            
            for alg in algorithms:
                if alg in algorithm_info:
                    self.help_text.insert(tk.END, f"【{alg}】\n{algorithm_info[alg]}\n\n")
    
    def open_github(self):
        webbrowser.open('https://github.com/qwerasdzx-123/crypto_gui')
    
    def toggle_theme(self):
        new_theme = self.theme_manager.toggle_theme()
        self.apply_theme()
        
        if new_theme == 'dark':
            self.theme_button.config(text="☀️")
        else:
            self.theme_button.config(text="🌙")
    
    def apply_theme(self):
        bg = self.theme_manager.get_color('background')
        surface = self.theme_manager.get_color('surface')
        card = self.theme_manager.get_color('card')
        text = self.theme_manager.get_color('text')
        text_secondary = self.theme_manager.get_color('text_secondary')
        primary = self.theme_manager.get_color('primary')
        input_bg = self.theme_manager.get_color('input_bg')
        
        self.main_container.config(bg=bg)
        self.header.config(bg=bg)
        self.header_left.config(bg=bg)
        self.header_right.config(bg=bg)
        self.title_label.config(bg=bg, fg=text)
        self.github_button.config(bg=surface, fg=text)
        self.theme_button.config(bg=surface, fg=text)
        
        self.tab_frame.config(bg=bg)
        for tab in self.tabs:
            tab.config(bg=bg, fg=text_secondary)
        
        for content in self.tab_contents:
            content.config(bg=bg)
        
        self._apply_theme_recursive(self.main_container)
    
    def _apply_theme_recursive(self, widget):
        bg = self.theme_manager.get_color('background')
        card = self.theme_manager.get_color('card')
        text = self.theme_manager.get_color('text')
        text_secondary = self.theme_manager.get_color('text_secondary')
        primary = self.theme_manager.get_color('primary')
        input_bg = self.theme_manager.get_color('input_bg')
        
        if isinstance(widget, tk.Frame):
            try:
                widget.config(bg=bg)
            except:
                pass
        
        for child in widget.winfo_children():
            if isinstance(child, tk.Frame):
                try:
                    child.config(bg=bg)
                except:
                    pass
            elif isinstance(child, tk.Label):
                try:
                    if 'title' in str(child):
                        child.config(bg=bg, fg=text)
                    elif 'heading' in str(child):
                        child.config(bg=card, fg=text)
                    elif 'info' in str(child) or 'status' in str(child):
                        child.config(bg=card, fg=text_secondary)
                    else:
                        child.config(bg=bg, fg=text)
                except:
                    pass
            elif isinstance(child, tk.Entry):
                try:
                    child.config(bg=input_bg, fg=text, insertbackground=primary)
                except:
                    pass
            elif isinstance(child, tk.Button):
                try:
                    if child != self.github_button and child != self.theme_button:
                        child.config(bg=primary, fg='white')
                except:
                    pass
            elif isinstance(child, scrolledtext.ScrolledText):
                try:
                    child.config(bg=input_bg, fg=text, insertbackground=primary)
                except:
                    pass
            
            try:
                self._apply_theme_recursive(child)
            except:
                pass


def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
