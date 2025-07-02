#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简化版 Octra 钱包 GUI
修复版本，避免复杂的主题和样式问题
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import json
import base64
import urllib.request
import ssl
import threading
import socket
import sys
import pyperclip
import queue
import time
from datetime import datetime
import secrets
import hashlib
import hmac
import os
from typing import Dict, List, Tuple, Optional

# 导入加密库
try:
    import nacl.signing
    import nacl.encoding
    from mnemonic import Mnemonic
except ImportError as e:
    print(f"❌ 导入错误: {e}")
    print("请安装必要的包:")
    print("pip install PyNaCl pyperclip mnemonic")
    sys.exit(1)

# Base58字母表 (Bitcoin风格)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

class OctraWalletGenerator:
    """Octra钱包生成器类"""
    
    def __init__(self):
        self.mnemo = Mnemonic("english")
        
    def generate_entropy(self, strength: int = 128) -> bytes:
        """生成加密安全的随机熵"""
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("熵强度必须是 128, 160, 192, 224 或 256 位")
        
        return secrets.token_bytes(strength // 8)
    
    def derive_master_key(self, seed: bytes) -> Tuple[bytes, bytes]:
        """使用HMAC-SHA512和"Octra seed"派生主密钥"""
        key = b"Octra seed"
        mac = hmac.new(key, seed, hashlib.sha512).digest()
        master_private_key = mac[:32]
        master_chain_code = mac[32:64]
        return master_private_key, master_chain_code
    
    def base58_encode(self, data: bytes) -> str:
        """Base58编码"""
        if not data:
            return ""
        
        # 转换为整数
        num = int.from_bytes(data, 'big')
        encoded = ""
        
        while num > 0:
            remainder = num % 58
            num = num // 58
            encoded = BASE58_ALPHABET[remainder] + encoded
        
        # 处理前导零
        for byte in data:
            if byte == 0:
                encoded = "1" + encoded
            else:
                break
        
        return encoded
    
    def create_octra_address(self, public_key: bytes) -> str:
        """创建Octra地址"""
        hash_digest = hashlib.sha256(public_key).digest()
        base58_hash = self.base58_encode(hash_digest)
        return "oct" + base58_hash
    
    def verify_address_format(self, address: str) -> bool:
        """验证地址格式"""
        if not address.startswith("oct"):
            return False
        if len(address) != 47:  # oct + 44字符的base58
            return False
        
        base58_part = address[3:]
        for char in base58_part:
            if char not in BASE58_ALPHABET:
                return False
        
        return True
    
    def generate_wallet(self, entropy_strength: int = 128) -> Dict:
        """生成完整的Octra钱包"""
        # 1. 生成熵
        entropy = self.generate_entropy(entropy_strength)
        
        # 2. 创建助记词
        mnemonic = self.mnemo.to_mnemonic(entropy)
        mnemonic_words = mnemonic.split(" ")
        
        # 3. 从助记词派生种子
        seed = self.mnemo.to_seed(mnemonic)
        
        # 4. 派生主密钥
        master_private_key, master_chain_code = self.derive_master_key(seed)
        
        # 5. 创建Ed25519密钥对
        signing_key = nacl.signing.SigningKey(master_private_key)
        private_key_raw = signing_key.encode()[:32]  # 只取前32字节作为私钥
        public_key_raw = signing_key.verify_key.encode()
        
        # 6. 生成Octra地址
        address = self.create_octra_address(public_key_raw)
        
        # 7. 验证地址格式
        if not self.verify_address_format(address):
            raise ValueError("生成的地址格式无效")
        
        # 8. 签名测试
        test_message = '{"from":"test","to":"test","amount":"1000000","nonce":1}'
        test_signature = signing_key.sign(test_message.encode()).signature
        
        # 验证签名
        try:
            verify_key = nacl.signing.VerifyKey(public_key_raw)
            verify_key.verify(test_message.encode(), test_signature)
            signature_valid = True
        except Exception:
            signature_valid = False
        
        # 9. 构建钱包数据
        wallet_data = {
            "mnemonic": mnemonic_words,
            "seed_hex": seed.hex(),
            "master_chain_hex": master_chain_code.hex(),
            "private_key_hex": private_key_raw.hex(),
            "public_key_hex": public_key_raw.hex(),
            "private_key_b64": base64.b64encode(private_key_raw).decode(),
            "public_key_b64": base64.b64encode(public_key_raw).decode(),
            "address": address,
            "entropy_hex": entropy.hex(),
            "test_message": test_message,
            "test_signature": base64.b64encode(test_signature).decode(),
            "signature_valid": signature_valid,
            "generated_at": datetime.now().isoformat(),
            "entropy_strength": entropy_strength
        }
        
        return wallet_data

# 多钱包支持的钱包核心类
class MultiWalletCore:
    def __init__(self):
        self.wallets = {}  # 存储所有钱包
        self.current_wallet_name = None  # 当前选中的钱包名称
        self.default_rpc = 'https://octra.network'
        self.μ = 1_000_000
        
    def load_wallets(self, wallet_file='wallet.json'):
        """加载钱包配置文件，支持单钱包和多钱包格式"""
        try:
            with open(wallet_file, 'r') as f:
                data = json.load(f)
            
            # 检查是否为旧的单钱包格式
            if 'priv' in data and 'addr' in data:
                # 转换为新的多钱包格式
                self.default_rpc = data.get('rpc', 'https://octra.network')
                self.wallets = {
                    '主钱包': {
                        'name': '主钱包',
                        'priv': data['priv'],
                        'addr': data['addr'],
                        'rpc': data.get('rpc', self.default_rpc),
                        'balance': 0.0,
                        'nonce': 0,
                        'transaction_history': []
                    }
                }
                self.current_wallet_name = '主钱包'
                
                # 自动转换并保存新格式
                self.save_wallets(wallet_file)
                
            # 新的多钱包格式
            elif 'wallets' in data:
                self.default_rpc = data.get('default_rpc', 'https://octra.network')
                self.wallets = {}
                
                for name, wallet_data in data['wallets'].items():
                    self.wallets[name] = {
                        'name': wallet_data.get('name', name),
                        'priv': wallet_data['priv'],
                        'addr': wallet_data['addr'],
                        'rpc': wallet_data.get('rpc', self.default_rpc),
                        'balance': 0.0,
                        'nonce': 0,
                        'transaction_history': []
                    }
                
                # 设置默认钱包
                if self.wallets:
                    self.current_wallet_name = list(self.wallets.keys())[0]
            
            else:
                # 如果文件格式无效，创建默认钱包
                self.create_default_wallet()
                
            print(f"✅ 成功加载 {len(self.wallets)} 个钱包")
            return True
            
        except FileNotFoundError:
            print("❌ 钱包文件不存在，创建默认配置")
            self.create_default_wallet()
            return True
        except Exception as e:
            print(f"❌ 加载钱包失败: {e}")
            return False
    
    def create_default_wallet(self):
        """创建默认钱包配置"""
        self.wallets = {
            '默认钱包': {
                'name': '默认钱包',
                'priv': 'private key here',
                'addr': 'octBTwBj3qzTmchqyb4xW6Trfi3t4D2eebMYsMQuHaWh4ET',
                'rpc': self.default_rpc,
                'balance': 0.0,
                'nonce': 0,
                'transaction_history': []
            }
        }
        self.current_wallet_name = '默认钱包'
    
    def save_wallets(self, wallet_file='wallet.json'):
        """保存钱包配置到文件"""
        try:
            # 准备保存的数据（去除运行时数据）
            save_data = {
                'default_rpc': self.default_rpc,
                'wallets': {}
            }
            
            for name, wallet in self.wallets.items():
                save_data['wallets'][name] = {
                    'name': wallet['name'],
                    'priv': wallet['priv'],
                    'addr': wallet['addr'],
                    'rpc': wallet['rpc']
                }
            
            with open(wallet_file, 'w') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ 钱包配置已保存")
            return True
            
        except Exception as e:
            print(f"❌ 保存钱包配置失败: {e}")
            return False
    
    def get_current_wallet(self):
        """获取当前选中的钱包"""
        if self.current_wallet_name and self.current_wallet_name in self.wallets:
            return self.wallets[self.current_wallet_name]
        return None
    
    def set_current_wallet(self, wallet_name):
        """设置当前钱包"""
        if wallet_name in self.wallets:
            self.current_wallet_name = wallet_name
            return True
        return False
    
    def get_wallet_list(self):
        """获取所有钱包名称列表"""
        return list(self.wallets.keys())
    
    def add_wallet(self, name, priv, addr, rpc=None):
        """添加新钱包"""
        if name in self.wallets:
            return False, "钱包名称已存在"
        
        self.wallets[name] = {
            'name': name,
            'priv': priv,
            'addr': addr,
            'rpc': rpc or self.default_rpc,
            'balance': 0.0,
            'nonce': 0,
            'transaction_history': []
        }
        
        # 如果这是第一个钱包，设为当前钱包
        if not self.current_wallet_name:
            self.current_wallet_name = name
            
        return True, "钱包添加成功"
    
    def remove_wallet(self, name):
        """删除钱包"""
        if name not in self.wallets:
            return False, "钱包不存在"
        
        if len(self.wallets) <= 1:
            return False, "至少需要保留一个钱包"
        
        del self.wallets[name]
        
        # 如果删除的是当前钱包，选择另一个
        if self.current_wallet_name == name:
            self.current_wallet_name = list(self.wallets.keys())[0]
        
        return True, "钱包删除成功"
    
    def get_balance_sync(self, wallet_name=None):
        """获取指定钱包的余额"""
        wallet_name = wallet_name or self.current_wallet_name
        if not wallet_name or wallet_name not in self.wallets:
            return None, None
        
        wallet = self.wallets[wallet_name]
        
        try:
            import urllib.request
            import json
            import ssl
            
            print(f"🌐 正在连接到: {wallet['rpc']}")
            print(f"📍 查询地址 ({wallet_name}): {wallet['addr']}")
            
            # 真实获取余额
            url = f"{wallet['rpc']}/balance/{wallet['addr']}"
            
            # 创建SSL上下文，忽略证书验证（仅用于测试）
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # 增加超时时间到15秒
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Octra-MultiWallet/1.0')
            
            with urllib.request.urlopen(req, timeout=15, context=ssl_context) as response:
                print(f"✅ 服务器响应状态: {response.status}")
                raw_data = response.read().decode()
                
                data = json.loads(raw_data)
                nonce = int(data.get('nonce', 0))
                balance = float(data.get('balance', 0))
                
                # 更新钱包信息
                wallet['nonce'] = nonce
                wallet['balance'] = balance
                
                print(f"💰 {wallet_name} 余额: {balance}, Nonce: {nonce}")
                return nonce, balance
                
        except Exception as e:
            error_msg = f"获取余额失败: {e}"
            print(f"❌ {error_msg}")
            # 返回缓存的值
            return wallet['nonce'], wallet['balance']
    


    def send_transaction_sync(self, to_address, amount, message=None, from_wallet=None):
        """从指定钱包发送交易"""
        from_wallet = from_wallet or self.current_wallet_name
        if not from_wallet or from_wallet not in self.wallets:
            return False, "发送方钱包不存在"
        
        wallet = self.wallets[from_wallet]
        
        try:
            import ssl
            
            print(f"💸 准备从 {from_wallet} 发送交易: {amount} OCT 到 {to_address}")
            
            # 获取最新状态
            nonce, balance = self.get_balance_sync(from_wallet)
            if nonce is None or balance is None:
                return False, "无法获取账户信息"
            
            if balance < float(amount):
                return False, f"余额不足: {from_wallet} 余额 {balance} OCT，需要 {amount} OCT"
            
            # 创建交易
            import base64
            import nacl.signing
            import hashlib
            
            timestamp = int(time.time() * 1000)
            amount_raw = int(float(amount) * self.μ)
            
            tx_data = {
                'from': wallet['addr'],
                'to': to_address,
                'amount': amount_raw,
                'nonce': nonce + 1,
                'timestamp': timestamp
            }
            
            if message:
                tx_data['data'] = json.dumps({'message': message})
            
            # 签名
            sk = nacl.signing.SigningKey(base64.b64decode(wallet['priv']))
            tx_json = json.dumps(tx_data, separators=(',', ':'))
            tx_hash = hashlib.sha256(tx_json.encode()).hexdigest()
            signature = base64.b64encode(sk.sign(tx_hash.encode()).signature).decode()
            
            full_tx = {
                'tx': tx_data,
                'hash': tx_hash,
                'signature': signature,
                'public_key': base64.b64encode(sk.verify_key.encode()).decode()
            }
            
            # 发送交易
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            submit_data = json.dumps(full_tx).encode()
            req = urllib.request.Request(
                f"{wallet['rpc']}/submit",
                data=submit_data,
                headers={'Content-Type': 'application/json', 'User-Agent': 'Octra-MultiWallet/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=15, context=ssl_context) as response:
                result = json.loads(response.read().decode())
                if result.get('success'):
                    print(f"✅ 交易发送成功! Hash: {tx_hash}")
                    # 更新本地nonce
                    wallet['nonce'] = nonce + 1
                    return True, f"交易发送成功!\n交易哈希: {tx_hash}"
                else:
                    return False, f"交易提交失败: {result.get('error', '未知错误')}"
                    
        except Exception as e:
            error_msg = f"发送交易失败: {e}"
            print(f"❌ {error_msg}")
            return False, error_msg

    def get_transaction_history_sync(self, wallet_name=None):
        """获取指定钱包的交易历史"""
        wallet_name = wallet_name or self.current_wallet_name
        if not wallet_name or wallet_name not in self.wallets:
            return False
        
        wallet = self.wallets[wallet_name]
        
        try:
            import ssl
            import urllib.request
            import json
            print(f"🌐 正在获取 {wallet_name} 的交易历史...")
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # 获取地址信息和交易历史
            url = f"{wallet['rpc']}/address/{wallet['addr']}?limit=20"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Octra-MultiWallet/1.0')
            
            with urllib.request.urlopen(req, timeout=15, context=ssl_context) as response:
                data = json.loads(response.read().decode())
            
            if 'recent_transactions' in data:
                history = []
                for ref in data['recent_transactions'][:10]:  # 限制前10条以提高性能
                    tx_hash = ref.get('hash', '')
                    try:
                        # 获取交易详情
                        tx_url = f"{wallet['rpc']}/tx/{tx_hash}"
                        tx_req = urllib.request.Request(tx_url)
                        tx_req.add_header('User-Agent', 'Octra-MultiWallet/1.0')
                        
                        with urllib.request.urlopen(tx_req, timeout=10, context=ssl_context) as tx_response:
                            tx_data = json.loads(tx_response.read().decode())
                        
                        if 'parsed_tx' in tx_data:
                            parsed = tx_data['parsed_tx']
                            is_incoming = parsed.get('to') == wallet['addr']
                            amount = float(parsed.get('amount', 0)) / self.μ
                            
                            history.append({
                                'time': datetime.fromtimestamp(parsed.get('timestamp', 0)),
                                'hash': tx_hash,
                                'amount': amount,
                                'from': parsed.get('from'),
                                'to': parsed.get('to'),
                                'type': 'in' if is_incoming else 'out'
                            })
                    except:
                        continue  # 跳过无法获取的交易
                
                wallet['transaction_history'] = history
                print(f"📊 获得 {len(history)} 条交易记录")
                return True
            return False
        except Exception as e:
            print(f"获取交易历史失败: {e}")
            return False

    def clear_history(self, wallet_name=None):
        """清除指定钱包的历史记录"""
        wallet_name = wallet_name or self.current_wallet_name
        if wallet_name in self.wallets:
            self.wallets[wallet_name]['transaction_history'] = []
            return True
        return False

class MultiWalletGUI:
    def __init__(self):
        self.wallet_core = MultiWalletCore()
        self.root = tk.Tk()
        self.wallet_core.load_wallets()
        
        # GUI组件引用
        self.wallet_selector = None
        self.balance_label = None
        self.address_label = None
        self.nonce_label = None
        
        # 线程安全的GUI更新队列
        self.gui_queue = queue.Queue()
        
        self.setup_ui()
        
        # 启动GUI更新检查
        self.check_gui_updates()
    
    def check_gui_updates(self):
        """检查GUI更新队列并处理更新"""
        try:
            while True:
                # 非阻塞获取队列中的更新任务
                update_task = self.gui_queue.get_nowait()
                task_type = update_task.get('type')
                
                if task_type == 'balance_update':
                    balance = update_task.get('balance')
                    nonce = update_task.get('nonce')
                    print(f"📍 处理GUI更新队列: 余额 {balance:.1f} OCT, Nonce {nonce}")
                    
                    try:
                        if hasattr(self, 'balance_label') and self.balance_label:
                            print(f"💰 更新余额标签: {balance:.1f} OCT")
                            self.balance_label.config(text=f"余额: {balance:.1f} OCT")
                            
                        if hasattr(self, 'nonce_label') and self.nonce_label:
                            print(f"🔢 更新Nonce标签: {nonce}")
                            self.nonce_label.config(text=f"Nonce: {nonce}")
                            
                        if hasattr(self, 'status_label') and self.status_label:
                            print(f"📊 更新状态标签")
                            self.status_label.config(text="✅ 余额已更新")
                            
                        print(f"✅ GUI已更新: 余额 {balance:.1f} OCT, Nonce {nonce}")
                        
                    except Exception as e:
                        print(f"💥 GUI更新异常: {e}")
                        
                elif task_type == 'error_update':
                    message = update_task.get('message', '❌ 未知错误')
                    print(f"📍 处理GUI错误更新: {message}")
                    
                    try:
                        if hasattr(self, 'status_label') and self.status_label:
                            self.status_label.config(text=message)
                            print(f"✅ 错误状态已更新: {message}")
                    except Exception as e:
                        print(f"💥 错误状态更新异常: {e}")
                        
        except queue.Empty:
            # 队列为空，继续
            pass
        except Exception as e:
            print(f"💥 检查GUI更新队列异常: {e}")
        
        # 每100毫秒检查一次
        self.root.after(100, self.check_gui_updates)
        
    def setup_ui(self):
        """设置用户界面"""
        self.root.title("Octra 测试网工具 by 晚风(x.com/pl_wanfeng)")
        self.root.geometry("800x700")
        self.root.configure(bg='#2d3748')
        
        # 主框架
        main_frame = tk.Frame(self.root, bg='#2d3748')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 标题
        title_label = tk.Label(
            main_frame,
            text="🔐 领水地址：https://faucet.octra.network/",
            font=('Arial', 20, 'bold'),
            fg='#63b3ed',
            bg='#2d3748',
            anchor='center'
        )
        title_label.pack(pady=(0, 20), fill=tk.X)
        
        # 钱包选择框
        wallet_frame = tk.Frame(main_frame, bg='#4a5568', relief=tk.RAISED, bd=2)
        wallet_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            wallet_frame,
            text="选择钱包:",
            font=('Arial', 12, 'bold'),
            fg='#e2e8f0',
            bg='#4a5568'
        ).pack(side=tk.LEFT, padx=10, pady=10)
        
        self.wallet_selector = ttk.Combobox(
            wallet_frame,
            values=self.wallet_core.get_wallet_list(),
            state="readonly",
            font=('Arial', 11)
        )
        self.wallet_selector.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
        
        if self.wallet_core.current_wallet_name:
            self.wallet_selector.set(self.wallet_core.current_wallet_name)
        
        self.wallet_selector.bind('<<ComboboxSelected>>', self.on_wallet_changed)
        
        # 钱包管理按钮
        wallet_btn_frame = tk.Frame(wallet_frame, bg='#4a5568')
        wallet_btn_frame.pack(side=tk.RIGHT, padx=10, pady=5)
        
        add_wallet_btn = tk.Button(
            wallet_btn_frame,
            text="➕ 添加钱包",
            font=('Arial', 10),
            bg='#48bb78',
            fg='black',
            activebackground='#38a169',
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.show_add_wallet_dialog
        )
        add_wallet_btn.pack(side=tk.LEFT, padx=2)
        
        create_wallet_btn = tk.Button(
            wallet_btn_frame,
            text="🎲 创建钱包",
            font=('Arial', 10),
            bg='#9f7aea',
            fg='black',
            activebackground='#805ad5',
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.show_create_wallet_dialog
        )
        create_wallet_btn.pack(side=tk.LEFT, padx=2)
        
        remove_wallet_btn = tk.Button(
            wallet_btn_frame,
            text="🗑️ 删除钱包",
            font=('Arial', 10),
            bg='#f56565',
            fg='black',
            activebackground='#e53e3e',
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.remove_current_wallet
        )
        remove_wallet_btn.pack(side=tk.LEFT, padx=2)
        
        # 当前钱包信息卡片
        info_frame = tk.Frame(main_frame, bg='#4a5568', relief=tk.RAISED, bd=2)
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            info_frame,
            text="💰 当前钱包信息",
            font=('Arial', 14, 'bold'),
            fg='#fbb6ce',
            bg='#4a5568',
            anchor='center'
        ).pack(pady=(10, 5), fill=tk.X)
        
        # 余额显示
        self.balance_label = tk.Label(
            info_frame,
            text="余额: 点击刷新",
            font=('Arial', 16, 'bold'),
            fg='#68d391',
            bg='#4a5568',
            anchor='center'
        )
        self.balance_label.pack(pady=5, fill=tk.X)
        
        # 地址显示
        self.address_label = tk.Label(
            info_frame,
            text="地址: --",
            font=('Arial', 10),
            fg='#cbd5e0',
            bg='#4a5568',
            wraplength=750,
            anchor='center',
            justify='center'
        )
        self.address_label.pack(pady=2, fill=tk.X)
        
        # Nonce显示
        self.nonce_label = tk.Label(
            info_frame,
            text="Nonce: --",
            font=('Arial', 10),
            fg='#cbd5e0',
            bg='#4a5568',
            anchor='center'
        )
        self.nonce_label.pack(pady=(2, 10), fill=tk.X)
        
        # 操作按钮区域
        button_frame = tk.Frame(main_frame, bg='#2d3748')
        button_frame.pack(fill=tk.X, pady=15)
        
        # 第一行按钮
        row1_frame = tk.Frame(button_frame, bg='#2d3748')
        row1_frame.pack(fill=tk.X, pady=3)
        
        buttons_row1 = [
            ("🔄 刷新余额", '#4299e1', self.refresh_balance),
            ("💸 发送交易", '#ed8936', self.show_send_dialog),
            ("📤 批量发送", '#9f7aea', self.show_multi_send_dialog),
        ]
        
        for text, color, command in buttons_row1:
            btn = tk.Button(
                row1_frame,
                text=text,
                font=('Arial', 12, 'bold'),
                bg=color,
                fg='black',
                activebackground=color,
                relief=tk.FLAT,
                padx=5,
                pady=12,
                command=command,
                cursor='hand2',
                width=16
            )
            btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=8, pady=2)
        
        # 第二行按钮
        row2_frame = tk.Frame(button_frame, bg='#2d3748')
        row2_frame.pack(fill=tk.X, pady=3)
        
        buttons_row2 = [
            ("📊 交易历史", '#38b2ac', self.show_transaction_history),
            ("💾 导出钱包", '#805ad5', self.show_export_dialog),
            ("🗑️ 清除历史", '#e53e3e', self.clear_history),
        ]
        
        for text, color, command in buttons_row2:
            btn = tk.Button(
                row2_frame,
                text=text,
                font=('Arial', 12, 'bold'),
                bg=color,
                fg='black',
                activebackground=color,
                relief=tk.FLAT,
                padx=5,
                pady=12,
                command=command,
                cursor='hand2',
                width=16
            )
            btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=8, pady=2)
        
        # 第三行按钮（工具）
        row3_frame = tk.Frame(button_frame, bg='#2d3748')
        row3_frame.pack(fill=tk.X, pady=3)
        
        # 创建一个居中的容器框架
        center_frame = tk.Frame(row3_frame, bg='#2d3748')
        center_frame.pack(expand=True)
        
        buttons_row3 = [
            ("🌐 网络测试", '#4a5568', self.test_network_connection),
        ]
        
        for text, color, command in buttons_row3:
            btn = tk.Button(
                center_frame,
                text=text,
                font=('Arial', 12, 'bold'),
                bg=color,
                fg='white',
                activebackground='#718096',
                relief=tk.FLAT,
                padx=5,
                pady=12,
                command=command,
                cursor='hand2',
                width=20
            )
            btn.pack(padx=8, pady=2)
        
        # 状态栏
        status_frame = tk.Frame(main_frame, bg='#1a202c', relief=tk.SUNKEN, bd=1)
        status_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.status_label = tk.Label(
            status_frame,
            text="✅ 就绪",
            font=('Arial', 10),
            fg='#68d391',
            bg='#1a202c',
            anchor='center'
        )
        self.status_label.pack(pady=8, fill=tk.X)
        
        # 更新当前钱包信息
        self.update_current_wallet_info()
        
        # 退出处理
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

    def on_wallet_changed(self, event=None):
        """钱包选择改变时的处理"""
        selected = self.wallet_selector.get()
        if selected and selected != self.wallet_core.current_wallet_name:
            old_wallet = self.wallet_core.current_wallet_name
            self.wallet_core.set_current_wallet(selected)
            self.update_current_wallet_info()
            self.status_label.config(text=f"✅ 已切换到: {selected}")
            print(f"🔄 钱包切换: {old_wallet} -> {selected}")
            
            # 切换钱包后提示用户刷新余额
            print("💡 钱包已切换，请点击'🔄 刷新余额'按钮获取余额")

    def update_current_wallet_info(self):
        """更新当前钱包信息显示"""
        wallet = self.wallet_core.get_current_wallet()
        if wallet:
            # 显示钱包基本信息
            self.address_label.config(text=f"地址: {wallet['addr']}")
            
            # 显示基本信息，余额由手动刷新
            self.balance_label.config(text="余额: 点击刷新")
            self.nonce_label.config(text="Nonce: --")
            print(f"💰 显示钱包 {wallet['name']} 信息，需手动刷新余额")
        else:
            self.balance_label.config(text="余额: -- OCT")
            self.address_label.config(text="地址: --")
            self.nonce_label.config(text="Nonce: --")

    def show_add_wallet_dialog(self):
        """显示添加钱包对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("添加新钱包")
        dialog.geometry("500x400")
        dialog.configure(bg='#2d3748')
        dialog.transient(self.root)
        dialog.grab_set()

        # 居中显示
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))

        tk.Label(dialog, text="添加新钱包", font=('Arial', 16, 'bold'), 
                fg='#63b3ed', bg='#2d3748').pack(pady=10)

        # 钱包名称
        tk.Label(dialog, text="钱包名称:", font=('Arial', 12), 
                fg='#e2e8f0', bg='#2d3748').pack(anchor='w', padx=20)
        name_entry = tk.Entry(dialog, font=('Arial', 11), width=50)
        name_entry.pack(padx=20, pady=(5, 10))

        # 私钥
        tk.Label(dialog, text="私钥:", font=('Arial', 12), 
                fg='#e2e8f0', bg='#2d3748').pack(anchor='w', padx=20)
        priv_entry = tk.Entry(dialog, font=('Arial', 11), width=50, show='*')
        priv_entry.pack(padx=20, pady=(5, 10))

        # 地址
        tk.Label(dialog, text="地址:", font=('Arial', 12), 
                fg='#e2e8f0', bg='#2d3748').pack(anchor='w', padx=20)
        addr_entry = tk.Entry(dialog, font=('Arial', 11), width=50)
        addr_entry.pack(padx=20, pady=(5, 10))

        # RPC节点（可选）
        tk.Label(dialog, text="RPC节点（可选）:", font=('Arial', 12), 
                fg='#e2e8f0', bg='#2d3748').pack(anchor='w', padx=20)
        rpc_entry = tk.Entry(dialog, font=('Arial', 11), width=50)
        rpc_entry.insert(0, self.wallet_core.default_rpc)
        rpc_entry.pack(padx=20, pady=(5, 20))

        # 按钮
        btn_frame = tk.Frame(dialog, bg='#2d3748')
        btn_frame.pack(pady=10)

        def add_wallet():
            name = name_entry.get().strip()
            priv = priv_entry.get().strip()
            addr = addr_entry.get().strip()
            rpc = rpc_entry.get().strip()

            if not name or not priv or not addr:
                messagebox.showerror("错误", "请填写所有必填字段")
                return

            success, msg = self.wallet_core.add_wallet(name, priv, addr, rpc)
            if success:
                # 保存钱包配置
                self.wallet_core.save_wallets()
                # 更新选择器
                self.wallet_selector['values'] = self.wallet_core.get_wallet_list()
                self.wallet_selector.set(name)
                self.wallet_core.set_current_wallet(name)
                self.update_current_wallet_info()
                dialog.destroy()
                messagebox.showinfo("成功", msg)
            else:
                messagebox.showerror("错误", msg)

        add_btn = tk.Button(btn_frame, text="添加", font=('Arial', 12, 'bold'),
                           bg='#48bb78', fg='black', padx=20, pady=5, command=add_wallet)
        add_btn.pack(side=tk.LEFT, padx=10)

        cancel_btn = tk.Button(btn_frame, text="取消", font=('Arial', 12, 'bold'),
                              bg='#718096', fg='black', padx=20, pady=5, command=dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=10)

    def remove_current_wallet(self):
        """删除当前钱包"""
        if not self.wallet_core.current_wallet_name:
            messagebox.showwarning("警告", "没有选中的钱包")
            return

        if len(self.wallet_core.wallets) <= 1:
            messagebox.showwarning("警告", "至少需要保留一个钱包")
            return

        result = messagebox.askyesno("确认删除", 
            f"确定要删除钱包 '{self.wallet_core.current_wallet_name}' 吗？\n此操作不可撤销！")
        
        if result:
            success, msg = self.wallet_core.remove_wallet(self.wallet_core.current_wallet_name)
            if success:
                self.wallet_core.save_wallets()
                # 更新界面
                self.wallet_selector['values'] = self.wallet_core.get_wallet_list()
                self.wallet_selector.set(self.wallet_core.current_wallet_name)
                self.update_current_wallet_info()
                messagebox.showinfo("成功", msg)
            else:
                messagebox.showerror("错误", msg)

    def show_create_wallet_dialog(self):
        """显示创建钱包对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("🎲 创建新钱包")
        dialog.geometry("500x500")
        dialog.configure(bg='#f0f0f0')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 标题
        title_label = tk.Label(dialog, text="🎲 创建新钱包", 
                              font=('Arial', 16, 'bold'),
                              bg='#f0f0f0', fg='#333333')
        title_label.pack(pady=20)
        
        # 主框架
        main_frame = tk.Frame(dialog, bg='#ffffff', relief='solid', bd=1)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 钱包数量选择
        tk.Label(main_frame, text="创建钱包数量:", 
                font=('Arial', 12, 'bold'),
                bg='#ffffff', fg='#333333').pack(anchor=tk.W, padx=20, pady=(20, 5))
        
        count_frame = tk.Frame(main_frame, bg='#ffffff')
        count_frame.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        count_var = tk.IntVar(value=1)
        count_spinbox = tk.Spinbox(count_frame, from_=1, to=100, textvariable=count_var,
                                  font=('Arial', 11), width=10)
        count_spinbox.pack(side=tk.LEFT)
        
        tk.Label(count_frame, text="(最多100个)", 
                font=('Arial', 10),
                bg='#ffffff', fg='#666666').pack(side=tk.LEFT, padx=(10, 0))
        
        # 钱包名称前缀
        tk.Label(main_frame, text="钱包名称前缀:", 
                font=('Arial', 12, 'bold'),
                bg='#ffffff', fg='#333333').pack(anchor=tk.W, padx=20, pady=(10, 5))
        
        prefix_entry = tk.Entry(main_frame, font=('Arial', 11), width=20)
        prefix_entry.pack(fill=tk.X, padx=20, pady=(0, 5))
        prefix_entry.insert(0, "钱包")
        
        tk.Label(main_frame, text="(例如：'钱包' -> 钱包1, 钱包2...)", 
                font=('Arial', 9),
                bg='#ffffff', fg='#888888').pack(anchor=tk.W, padx=20, pady=(0, 15))
        
        # 保存选项
        save_var = tk.BooleanVar(value=True)
        save_check = tk.Checkbutton(main_frame, text="保存钱包文件到本地", 
                                   variable=save_var, font=('Arial', 11),
                                   bg='#ffffff', fg='#333333')
        save_check.pack(anchor=tk.W, padx=20, pady=(10, 0))
        
        # 状态显示
        status_label = tk.Label(main_frame, text="准备就绪", 
                               font=('Arial', 10),
                               bg='#ffffff', fg='#007700')
        status_label.pack(anchor=tk.W, padx=20, pady=(10, 20))
        
        # 按钮框架
        btn_frame = tk.Frame(main_frame, bg='#ffffff')
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        def create_wallets():
            """创建钱包的任务函数"""
            try:
                count = count_var.get()
                prefix = prefix_entry.get().strip() or "钱包"
                save_files = save_var.get()
                
                if count < 1 or count > 100:
                    messagebox.showerror("错误", "钱包数量必须在1-100之间")
                    return
                
                # 禁用按钮
                create_btn.config(state='disabled')
                cancel_btn.config(state='disabled')
                
                # 初始化钱包生成器
                generator = OctraWalletGenerator()
                created_wallets = []
                saved_files = []
                failed_wallets = []
                
                for i in range(count):
                    # 更新状态
                    current = i + 1
                    status_label.config(text=f"🔄 正在创建第 {current}/{count} 个钱包...")
                    dialog.update()
                    
                    # 生成钱包（使用默认128位强度）
                    wallet_data = generator.generate_wallet(128)
                    
                    # 生成钱包名称
                    wallet_name = f"{prefix}{current}"
                    counter = 1
                    original_name = wallet_name
                    
                    # 避免重名
                    while wallet_name in self.wallet_core.wallets:
                        counter += 1
                        wallet_name = f"{original_name}_{counter}"
                    
                    # 添加到钱包管理器
                    success, msg = self.wallet_core.add_wallet(
                        wallet_name, 
                        wallet_data['private_key_hex'], 
                        wallet_data['address']
                    )
                    
                    if success:
                        created_wallets.append({
                            'name': wallet_name,
                            'address': wallet_data['address'],
                            'mnemonic': ' '.join(wallet_data['mnemonic'])
                        })
                        
                        # 保存文件（如果选择了）
                        if save_files:
                            timestamp = int(datetime.now().timestamp())
                            filename = f"{wallet_name}_{timestamp}.txt"
                            
                            content = f"""OCTRA WALLET
{"=" * 50}

⚠️  安全警告: 请安全保管此文件，切勿泄露私钥

钱包名称: {wallet_name}
创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

助记词 (Mnemonic):
{' '.join(wallet_data['mnemonic'])}

地址 (Address):
{wallet_data['address']}

私钥 (Private Key):
{wallet_data['private_key_hex']}

公钥 (Public Key):
{wallet_data['public_key_hex']}

⚠️  警告: 
- 请妥善保管您的助记词和私钥
- 不要将此文件存储在云服务上
- 丢失助记词将无法恢复钱包
"""
                            
                            try:
                                with open(filename, 'w', encoding='utf-8') as f:
                                    f.write(content)
                                saved_files.append(filename)
                            except Exception as e:
                                print(f"保存文件失败: {e}")
                    else:
                        print(f"❌ 添加钱包 {wallet_name} 失败: {msg}")
                        failed_wallets.append({
                            'name': wallet_name,
                            'error': msg
                        })
                        # 继续创建下一个钱包，而不是中断整个过程
                
                # 保存钱包配置
                self.wallet_core.save_wallets()
                
                # 更新界面
                self.wallet_selector['values'] = self.wallet_core.get_wallet_list()
                if created_wallets:
                    self.wallet_selector.set(created_wallets[-1]['name'])
                    self.wallet_core.set_current_wallet(created_wallets[-1]['name'])
                    self.update_current_wallet_info()
                
                # 完成
                if failed_wallets:
                    status_label.config(text=f"⚠️ 创建完成: 成功 {len(created_wallets)} 个，失败 {len(failed_wallets)} 个")
                else:
                    status_label.config(text=f"✅ 成功创建 {len(created_wallets)} 个钱包!")
                
                # 显示摘要
                if created_wallets:
                    summary = f"✅ 成功创建 {len(created_wallets)} 个钱包:\n\n"
                    for wallet in created_wallets:
                        summary += f"🔑 {wallet['name']}\n   {wallet['address']}\n\n"
                    
                    if saved_files:
                        summary += f"💾 已保存 {len(saved_files)} 个钱包文件到当前目录\n\n"
                    
                    if failed_wallets:
                        summary += f"❌ 失败 {len(failed_wallets)} 个钱包:\n"
                        for failed in failed_wallets:
                            summary += f"   {failed['name']}: {failed['error']}\n"
                    
                    messagebox.showinfo("创建完成", summary)
                else:
                    error_summary = f"❌ 所有钱包创建失败:\n\n"
                    for failed in failed_wallets:
                        error_summary += f"   {failed['name']}: {failed['error']}\n"
                    messagebox.showerror("创建失败", error_summary)
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("错误", f"创建钱包失败: {str(e)}")
            finally:
                # 恢复按钮
                create_btn.config(state='normal')
                cancel_btn.config(state='normal')
        
        def cancel():
            dialog.destroy()
        
        # 取消按钮
        cancel_btn = tk.Button(btn_frame, text="取消", command=cancel,
                              font=('Arial', 11, 'bold'),
                              bg='#cccccc', fg='black',
                              pady=8, width=12)
        cancel_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # 创建按钮
        create_btn = tk.Button(btn_frame, text="🎲 开始创建", command=create_wallets,
                              font=('Arial', 11, 'bold'),
                              bg='#4CAF50', fg='black',
                              pady=8, width=12)
        create_btn.pack(side=tk.RIGHT)

    def refresh_balance(self):
        """刷新当前钱包余额"""
        if not self.wallet_core.current_wallet_name:
            self.status_label.config(text="❌ 没有选中的钱包")
            return
            
        self.status_label.config(text="🔄 正在刷新余额...")
        
        def refresh_task():
            try:
                print(f"🔄 开始获取钱包 {self.wallet_core.current_wallet_name} 的余额...")
                nonce, balance = self.wallet_core.get_balance_sync()
                print(f"📊 API返回结果: nonce={nonce}, balance={balance}")
                
                if nonce is not None and balance is not None:
                    print(f"✅ 准备更新GUI: 余额 {balance:.1f} OCT, Nonce {nonce}")
                    
                    # 使用队列传递更新任务到主线程
                    update_task = {
                        'type': 'balance_update',
                        'balance': balance,
                        'nonce': nonce
                    }
                    
                    print(f"📤 将更新任务加入GUI队列: balance={balance:.1f}, nonce={nonce}")
                    self.gui_queue.put(update_task)
                    print(f"✅ 任务已加入队列")
                else:
                    print(f"❌ 获取余额失败: nonce={nonce}, balance={balance}")
                    # 使用队列更新错误状态
                    error_task = {
                        'type': 'error_update',
                        'message': "❌ 获取余额失败"
                    }
                    self.gui_queue.put(error_task)
                    
            except Exception as e:
                print(f"💥 刷新任务异常: {e}")
                # 使用队列更新异常状态
                error_task = {
                    'type': 'error_update',
                    'message': f"❌ 刷新失败: {str(e)}"
                }
                self.gui_queue.put(error_task)
        
        threading.Thread(target=refresh_task, daemon=True).start()



    def show_send_dialog(self):
        """显示发送交易对话框"""
        # 创建发送对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("发送交易")
        dialog.geometry("500x500")
        dialog.configure(bg='#2d3748')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 标题
        title_label = tk.Label(dialog, text="💸 发送交易", 
                              font=('Arial', 16, 'bold'),
                              bg='#2d3748', fg='#ffffff')
        title_label.pack(pady=(20, 30))
        
        # 表单框架
        form_frame = tk.Frame(dialog, bg='#4a5568', relief='flat', bd=2)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 发送方钱包选择
        tk.Label(form_frame, text="发送方钱包:", 
                font=('Arial', 12, 'bold'),
                bg='#4a5568', fg='#ffffff').pack(anchor=tk.W, padx=20, pady=(20, 5))
        
        from_wallet = ttk.Combobox(form_frame, values=self.wallet_core.get_wallet_list(), 
                                  state="readonly", font=('Arial', 11))
        from_wallet.pack(fill=tk.X, padx=20, pady=(0, 15))
        if self.wallet_core.current_wallet_name:
            from_wallet.set(self.wallet_core.current_wallet_name)
        
        # 收款地址
        tk.Label(form_frame, text="收款地址:", 
                font=('Arial', 12, 'bold'),
                bg='#4a5568', fg='#ffffff').pack(anchor=tk.W, padx=20, pady=5)
        
        addr_entry = tk.Entry(form_frame, font=('Courier', 10), width=50,
                             bg='#ffffff', fg='#000000', relief='flat', bd=5)
        addr_entry.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        # 金额
        tk.Label(form_frame, text="金额 (OCT):", 
                font=('Arial', 12, 'bold'),
                bg='#4a5568', fg='#ffffff').pack(anchor=tk.W, padx=20, pady=5)
        
        amount_entry = tk.Entry(form_frame, font=('Arial', 11), width=20,
                               bg='#ffffff', fg='#000000', relief='flat', bd=5)
        amount_entry.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        # 消息
        tk.Label(form_frame, text="消息 (可选):", 
                font=('Arial', 12, 'bold'),
                bg='#4a5568', fg='#ffffff').pack(anchor=tk.W, padx=20, pady=5)
        
        msg_entry = tk.Entry(form_frame, font=('Arial', 11), width=50,
                            bg='#ffffff', fg='#000000', relief='flat', bd=5)
        msg_entry.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        # 按钮框架
        btn_frame = tk.Frame(form_frame, bg='#4a5568')
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        def send_transaction():
            from_wallet_name = from_wallet.get().strip()
            to_address = addr_entry.get().strip()
            amount_str = amount_entry.get().strip()
            message = msg_entry.get().strip() or None
            
            # 验证输入
            if not from_wallet_name:
                messagebox.showerror("错误", "请选择发送方钱包")
                return
                
            if not to_address:
                messagebox.showerror("错误", "请输入收款地址")
                return
            
            # 简单的地址格式验证
            if not to_address.startswith('oct') or len(to_address) != 47:
                messagebox.showerror("错误", "无效的地址格式")
                return
            
            try:
                amount = float(amount_str)
                if amount <= 0:
                    raise ValueError()
            except ValueError:
                messagebox.showerror("错误", "请输入有效的金额")
                return
            
            # 确认发送
            confirm_msg = f"确认从 {from_wallet_name} 发送 {amount} OCT 到:\n{to_address}"
            if message:
                confirm_msg += f"\n\n消息: {message}"
            
            if not messagebox.askyesno("确认发送", confirm_msg):
                return
            
            # 发送交易
            success, result = self.wallet_core.send_transaction_sync(to_address, amount, message, from_wallet_name)
            if success:
                messagebox.showinfo("成功", result)
                dialog.destroy()
                # 如果发送方是当前钱包，刷新余额
                if from_wallet_name == self.wallet_core.current_wallet_name:
                    self.refresh_balance()
            else:
                messagebox.showerror("错误", result)
        
        def cancel():
            dialog.destroy()
        
        # 取消按钮
        cancel_btn = tk.Button(btn_frame, text="取消", command=cancel,
                              font=('Arial', 11, 'bold'),
                              bg='#718096', fg='black',
                              relief='flat', bd=0, pady=8, width=12)
        cancel_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # 发送按钮
        send_btn = tk.Button(btn_frame, text="发送", command=send_transaction,
                            font=('Arial', 11, 'bold'),
                            bg='#38a169', fg='black',
                            relief='flat', bd=0, pady=8, width=12)
        send_btn.pack(side=tk.RIGHT)
    
    def show_export_dialog(self):
        """显示导出对话框"""
        # 创建导出对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("导出钱包")
        dialog.geometry("500x500")
        dialog.configure(bg='#2d3748')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 标题
        title_label = tk.Label(dialog, text="💾 导出钱包", 
                              font=('Arial', 16, 'bold'),
                              bg='#2d3748', fg='#f7fafc')
        title_label.pack(pady=(20, 20))
        
        # 钱包选择框架
        wallet_frame = tk.Frame(dialog, bg='#2d3748')
        wallet_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(wallet_frame, text="选择要导出的钱包:", font=('Arial', 12, 'bold'), 
                fg='#e2e8f0', bg='#2d3748').pack(anchor='w')
        
        export_wallet = ttk.Combobox(wallet_frame, values=self.wallet_core.get_wallet_list(), 
                                    state="readonly", font=('Arial', 11))
        export_wallet.pack(fill=tk.X, pady=(5, 0))
        if self.wallet_core.current_wallet_name:
            export_wallet.set(self.wallet_core.current_wallet_name)
        
        # 选项框架
        options_frame = tk.Frame(dialog, bg='#4a5568', relief='flat', bd=2)
        options_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 显示私钥
        def show_private_key():
            selected_wallet = export_wallet.get()
            if not selected_wallet:
                messagebox.showerror("错误", "请选择要导出的钱包")
                return
                
            if messagebox.askyesno("警告", "私钥是敏感信息！\n确认要显示吗？"):
                key_window = tk.Toplevel(dialog)
                key_window.title(f"私钥信息 - {selected_wallet}")
                key_window.geometry("700x300")
                key_window.configure(bg='#2d3748')
                
                tk.Label(key_window, text=f"钱包: {selected_wallet}", 
                        font=('Arial', 14, 'bold'),
                        bg='#2d3748', fg='#63b3ed').pack(pady=(20, 10))
                
                tk.Label(key_window, text="私钥 (请妥善保管):", 
                        font=('Arial', 12, 'bold'),
                        bg='#2d3748', fg='#f56565').pack(pady=(0, 10))
                
                key_text = tk.Text(key_window, height=6, wrap=tk.WORD,
                                  font=('Courier', 10),
                                  bg='#4a5568', fg='#ffffff')
                key_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
                
                wallet_data = self.wallet_core.wallets[selected_wallet]
                key_info = f"私钥: {wallet_data['priv']}\n\n"
                key_info += f"地址: {wallet_data['addr']}\n\n"
                key_info += f"RPC节点: {wallet_data['rpc']}"
                key_text.insert(tk.END, key_info)
                key_text.config(state=tk.DISABLED)
                
                # 复制按钮
                copy_btn = tk.Button(key_window, text="📋 复制私钥", 
                                   command=lambda: self.copy_to_clipboard(wallet_data['priv'], "私钥已复制"),
                                   font=('Arial', 10, 'bold'), bg='#3182ce', fg='black')
                copy_btn.pack(pady=10)
        
        # 复制地址
        def copy_address():
            selected_wallet = export_wallet.get()
            if not selected_wallet:
                messagebox.showerror("错误", "请选择要导出的钱包")
                return
                
            try:
                dialog.clipboard_clear()
                dialog.clipboard_append(self.wallet_core.wallets[selected_wallet]['addr'])
                messagebox.showinfo("成功", f"{selected_wallet} 地址已复制到剪贴板！")
            except Exception as e:
                messagebox.showerror("错误", f"复制失败: {str(e)}")
        
        # 导出全部信息
        def export_all_info():
            selected_wallet = export_wallet.get()
            if not selected_wallet:
                messagebox.showerror("错误", "请选择要导出的钱包")
                return
                
            info_window = tk.Toplevel(dialog)
            info_window.title(f"完整信息 - {selected_wallet}")
            info_window.geometry("700x400")
            info_window.configure(bg='#2d3748')
            
            tk.Label(info_window, text=f"钱包完整信息 - {selected_wallet}", 
                    font=('Arial', 14, 'bold'),
                    bg='#2d3748', fg='#63b3ed').pack(pady=(20, 10))
            
            info_text = tk.Text(info_window, wrap=tk.WORD, font=('Courier', 10),
                               bg='#4a5568', fg='#ffffff')
            info_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
            
            wallet_data = self.wallet_core.wallets[selected_wallet]
            info_content = f"钱包名称: {wallet_data['name']}\n"
            info_content += f"地址: {wallet_data['addr']}\n"
            info_content += f"私钥: {wallet_data['priv']}\n"
            info_content += f"RPC节点: {wallet_data['rpc']}\n"
            info_content += f"当前余额: {wallet_data.get('balance', 0):.6f} OCT\n"
            info_content += f"当前Nonce: {wallet_data.get('nonce', 0)}\n"
            info_content += f"交易历史数量: {len(wallet_data.get('transaction_history', []))}\n"
            
            info_text.insert(tk.END, info_content)
            info_text.config(state=tk.DISABLED)
            
            # 复制全部按钮
            copy_all_btn = tk.Button(info_window, text="📋 复制全部信息", 
                                   command=lambda: self.copy_to_clipboard(info_content, "钱包信息已复制"),
                                   font=('Arial', 10, 'bold'), bg='#805ad5', fg='black')
            copy_all_btn.pack(pady=10)
        
        # 按钮
        tk.Button(options_frame, text="🔑 显示私钥", command=show_private_key,
                 font=('Arial', 11, 'bold'),
                 bg='#e53e3e', fg='black',
                 relief='flat', bd=0, pady=10).pack(fill=tk.X, padx=20, pady=(20, 10))
        
        tk.Button(options_frame, text="📋 复制地址", command=copy_address,
                 font=('Arial', 11, 'bold'),
                 bg='#3182ce', fg='black',
                 relief='flat', bd=0, pady=10).pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(options_frame, text="📄 完整信息", command=export_all_info,
                 font=('Arial', 11, 'bold'),
                 bg='#805ad5', fg='black',
                 relief='flat', bd=0, pady=10).pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(options_frame, text="关闭", command=dialog.destroy,
                 font=('Arial', 11, 'bold'),
                 bg='#718096', fg='black',
                 relief='flat', bd=0, pady=10).pack(fill=tk.X, padx=20, pady=(10, 20))
    
    def copy_to_clipboard(self, text, success_msg):
        """复制文本到剪贴板"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("成功", success_msg)
        except Exception as e:
            messagebox.showerror("错误", f"复制失败: {str(e)}")
    
    def test_network_connection(self):
        """测试网络连接"""
        test_window = tk.Toplevel(self.root)
        test_window.title("网络连接测试")
        test_window.geometry("600x600")
        test_window.configure(bg='#2d3748')
        test_window.transient(self.root)
        test_window.grab_set()
        
        # 标题
        title_label = tk.Label(test_window, text="🌐 网络连接诊断", 
                              font=('Arial', 16, 'bold'),
                              bg='#2d3748', fg='#f7fafc')
        title_label.pack(pady=(20, 30))
        
        # 信息框架
        info_frame = tk.Frame(test_window, bg='#4a5568', relief='flat', bd=2)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 当前配置
        config_label = tk.Label(info_frame, text="📋 当前配置", 
                               font=('Arial', 14, 'bold'),
                               bg='#4a5568', fg='#f7fafc')
        config_label.pack(pady=(15, 10))
        
        # RPC地址
        rpc_frame = tk.Frame(info_frame, bg='#4a5568')
        rpc_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(rpc_frame, text="RPC服务器:", 
                font=('Arial', 11, 'bold'),
                bg='#4a5568', fg='#e2e8f0').pack(side=tk.LEFT)
        
        rpc_label = tk.Label(rpc_frame, text=self.wallet_core.wallets[self.wallet_core.current_wallet_name]['rpc'], 
                            font=('Courier', 10),
                            bg='#4a5568', fg='#90cdf4')
        rpc_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # 测试结果区域
        result_label = tk.Label(info_frame, text="🔍 测试结果", 
                               font=('Arial', 14, 'bold'),
                               bg='#4a5568', fg='#f7fafc')
        result_label.pack(pady=(20, 10))
        
        # 结果文本框
        result_text = tk.Text(info_frame, height=15, wrap=tk.WORD,
                             font=('Courier', 9),
                             bg='#f7fafc', fg='#1a202c',
                             relief='flat', bd=5)
        result_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 按钮框架
        btn_frame = tk.Frame(info_frame, bg='#4a5568')
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        def run_test():
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "🚀 开始网络连接测试...\n\n")
            result_text.update()
            
            # 测试基本网络连接
            result_text.insert(tk.END, "1️⃣ 测试基本网络连接...\n")
            result_text.update()
            
            try:
                import urllib.request
                
                # 测试Google DNS
                start_time = time.time()
                urllib.request.urlopen("https://8.8.8.8", timeout=5)
                dns_time = time.time() - start_time
                result_text.insert(tk.END, f"   ✅ DNS连通性正常 ({dns_time:.2f}s)\n")
            except Exception as e:
                result_text.insert(tk.END, f"   ❌ DNS连通性失败: {e}\n")
            
            result_text.insert(tk.END, "\n2️⃣ 测试HTTPS连接...\n")
            result_text.update()
            
            try:
                start_time = time.time()
                urllib.request.urlopen("https://www.google.com", timeout=10)
                https_time = time.time() - start_time
                result_text.insert(tk.END, f"   ✅ HTTPS连接正常 ({https_time:.2f}s)\n")
            except Exception as e:
                result_text.insert(tk.END, f"   ❌ HTTPS连接失败: {e}\n")
            
            result_text.insert(tk.END, "\n3️⃣ 测试Octra RPC服务器...\n")
            result_text.update()
            
            try:
                import ssl
                
                url = f"{self.wallet_core.wallets[self.wallet_core.current_wallet_name]['rpc']}/balance/{self.wallet_core.wallets[self.wallet_core.current_wallet_name]['addr']}"
                result_text.insert(tk.END, f"   📡 连接地址: {url}\n")
                
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Octra-Wallet/1.0')
                
                start_time = time.time()
                with urllib.request.urlopen(req, timeout=20, context=ssl_context) as response:
                    rpc_time = time.time() - start_time
                    result_text.insert(tk.END, f"   ✅ RPC服务器响应正常 ({rpc_time:.2f}s)\n")
                    result_text.insert(tk.END, f"   📊 状态码: {response.status}\n")
                    
                    # 读取响应
                    data = response.read().decode()
                    result_text.insert(tk.END, f"   📥 响应长度: {len(data)} 字节\n")
                    
                    if len(data) > 100:
                        preview = data[:100] + "..."
                    else:
                        preview = data
                    result_text.insert(tk.END, f"   📄 响应预览: {preview}\n")
                    
            except Exception as e:
                result_text.insert(tk.END, f"   ❌ RPC服务器连接失败: {e}\n")
                result_text.insert(tk.END, "\n💡 建议解决方案:\n")
                result_text.insert(tk.END, "   • 检查网络连接\n")
                result_text.insert(tk.END, "   • 检查防火墙设置\n")
                result_text.insert(tk.END, "   • 尝试更换RPC服务器\n")
                result_text.insert(tk.END, "   • 稍后再试\n")
            
            result_text.insert(tk.END, "\n🏁 测试完成!\n")
            result_text.see(tk.END)
        
        # 测试按钮
        test_btn = tk.Button(btn_frame, text="🔍 开始测试", command=run_test,
                            font=('Arial', 11, 'bold'),
                            bg='#3182ce', fg='black',
                            relief='flat', bd=0, pady=8, width=15)
        test_btn.pack(side=tk.LEFT)
        
        # 关闭按钮
        close_btn = tk.Button(btn_frame, text="关闭", command=test_window.destroy,
                             font=('Arial', 11, 'bold'),
                             bg='#718096', fg='black',
                             relief='flat', bd=0, pady=8, width=15)
        close_btn.pack(side=tk.RIGHT)
    
    def show_multi_send_dialog(self):
        """显示批量发送对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("批量发送")
        dialog.geometry("600x600")
        dialog.configure(bg='#2d3748')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 标题
        title_label = tk.Label(dialog, text="📤 批量发送", 
                              font=('Arial', 16, 'bold'),
                              bg='#2d3748', fg='#f7fafc')
        title_label.pack(pady=(20, 10))
        
        # 说明
        info_label = tk.Label(dialog, text="格式: 地址,金额,消息(可选) - 每行一个", 
                             font=('Arial', 10),
                             bg='#2d3748', fg='#a0aec0')
        info_label.pack(pady=(0, 15))
        
        # 输入框架
        input_frame = tk.Frame(dialog, bg='#4a5568', relief='flat', bd=2)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 发送方钱包选择
        tk.Label(input_frame, text="发送方钱包:", 
                font=('Arial', 12, 'bold'),
                bg='#4a5568', fg='#e2e8f0').pack(anchor=tk.W, padx=20, pady=(20, 5))
        
        from_wallet = ttk.Combobox(input_frame, values=self.wallet_core.get_wallet_list(), 
                                  state="readonly", font=('Arial', 11))
        from_wallet.pack(fill=tk.X, padx=20, pady=(0, 15))
        if self.wallet_core.current_wallet_name:
            from_wallet.set(self.wallet_core.current_wallet_name)
        
        # 文本输入
        tk.Label(input_frame, text="批量发送列表:", 
                font=('Arial', 12, 'bold'),
                bg='#4a5568', fg='#e2e8f0').pack(anchor=tk.W, padx=20, pady=(20, 5))
        
        text_scroll = tk.Scrollbar(input_frame)
        text_area = tk.Text(input_frame, height=15, wrap=tk.WORD,
                           font=('Courier', 10),
                           bg='#f7fafc', fg='#1a202c',
                           yscrollcommand=text_scroll.set)
        text_scroll.config(command=text_area.yview)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 20))
        text_area.pack(fill=tk.BOTH, expand=True, padx=(20, 0), pady=(0, 15))
        
        # 示例文本
        example_text = """oct1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v,10.5,生日快乐
oct2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w,5.0
oct3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x,2.5,谢谢你"""
        text_area.insert(tk.END, example_text)
        
        # 按钮框架
        btn_frame = tk.Frame(input_frame, bg='#4a5568')
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        def execute_batch():
            from_wallet_name = from_wallet.get().strip()
            lines = text_area.get('1.0', tk.END).strip().split('\n')
            
            if not from_wallet_name:
                messagebox.showerror("错误", "请选择发送方钱包")
                return
                
            if not lines or lines == ['']:
                messagebox.showerror("错误", "请输入批量发送列表")
                return
            
            # 解析列表
            transactions = []
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split(',')
                if len(parts) < 2:
                    messagebox.showerror("错误", f"第{i}行格式错误")
                    return
                
                try:
                    addr = parts[0].strip()
                    amount = float(parts[1].strip())
                    message = parts[2].strip() if len(parts) > 2 else None
                    
                    if not addr.startswith('oct') or len(addr) != 47:
                        messagebox.showerror("错误", f"第{i}行地址格式错误")
                        return
                    
                    if amount <= 0:
                        messagebox.showerror("错误", f"第{i}行金额无效")
                        return
                    
                    transactions.append((addr, amount, message))
                except ValueError:
                    messagebox.showerror("错误", f"第{i}行金额格式错误")
                    return
            
            if not transactions:
                messagebox.showerror("错误", "没有有效的交易")
                return
            
            # 确认执行
            total_amount = sum(tx[1] for tx in transactions)
            confirm_msg = f"确认从 {from_wallet_name} 批量发送 {len(transactions)} 笔交易\n总金额: {total_amount} OCT"
            
            if not messagebox.askyesno("确认批量发送", confirm_msg):
                return
            
            # 执行批量发送
            success_count = 0
            failed_count = 0
            results = []
            
            for addr, amount, message in transactions:
                success, result = self.wallet_core.send_transaction_sync(addr, amount, message, from_wallet_name)
                if success:
                    success_count += 1
                    results.append(f"✅ {addr}: {amount} OCT")
                else:
                    failed_count += 1
                    results.append(f"❌ {addr}: {result}")
            
            # 显示结果
            result_msg = f"批量发送完成!\n成功: {success_count}, 失败: {failed_count}\n\n"
            result_msg += "\n".join(results[:10])  # 只显示前10条
            if len(results) > 10:
                result_msg += f"\n... 还有{len(results)-10}条记录"
            
            messagebox.showinfo("批量发送结果", result_msg)
            if success_count > 0:
                # 如果发送方是当前钱包，刷新余额
                if from_wallet_name == self.wallet_core.current_wallet_name:
                    self.refresh_balance()
            dialog.destroy()
        
        def cancel():
            dialog.destroy()
        
        # 取消按钮
        cancel_btn = tk.Button(btn_frame, text="取消", command=cancel,
                              font=('Arial', 11, 'bold'),
                              bg='#718096', fg='black',
                              relief='flat', bd=0, pady=8, width=12)
        cancel_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # 执行按钮
        send_btn = tk.Button(btn_frame, text="执行批量发送", command=execute_batch,
                            font=('Arial', 11, 'bold'),
                            bg='#319795', fg='black',
                            relief='flat', bd=0, pady=8, width=15)
        send_btn.pack(side=tk.RIGHT)
    
    def show_transaction_history(self):
        """显示交易历史"""
        dialog = tk.Toplevel(self.root)
        dialog.title("交易历史")
        dialog.geometry("900x600")
        dialog.configure(bg='#2d3748')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 标题
        title_label = tk.Label(dialog, text="📊 交易历史", 
                              font=('Arial', 16, 'bold'),
                              bg='#2d3748', fg='#f7fafc')
        title_label.pack(pady=(20, 10))
        
        # 钱包选择框架
        wallet_frame = tk.Frame(dialog, bg='#2d3748')
        wallet_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        tk.Label(wallet_frame, text="选择钱包:", font=('Arial', 12, 'bold'), 
                fg='#e2e8f0', bg='#2d3748').pack(side=tk.LEFT)
        
        # 导入ttk模块
        from tkinter import ttk
        
        wallet_selector = ttk.Combobox(wallet_frame, values=self.wallet_core.get_wallet_list(), 
                                      state="readonly", font=('Arial', 11))
        wallet_selector.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        if self.wallet_core.current_wallet_name:
            wallet_selector.set(self.wallet_core.current_wallet_name)
        
        # 刷新按钮
        refresh_btn = tk.Button(wallet_frame, text="🔄 刷新历史", font=('Arial', 10, 'bold'),
                               bg='#4299e1', fg='black', padx=10, pady=2)
        refresh_btn.pack(side=tk.RIGHT, padx=10)
        
        # 历史框架
        history_frame = tk.Frame(dialog, bg='#4a5568', relief='flat', bd=2)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # 创建Treeview显示历史
        
        # 列定义
        columns = ('time', 'type', 'amount', 'address', 'hash')
        tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=15)
        
        # 定义列标题
        tree.heading('time', text='时间')
        tree.heading('type', text='类型')
        tree.heading('amount', text='金额')
        tree.heading('address', text='对方地址')
        tree.heading('hash', text='交易哈希')
        
        # 设置列宽
        tree.column('time', width=150)
        tree.column('type', width=60)
        tree.column('amount', width=100)
        tree.column('address', width=200)
        tree.column('hash', width=200)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        # 放置控件
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 0), pady=20)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 20), pady=20)
        
        def update_history():
            """更新交易历史显示"""
            selected_wallet = wallet_selector.get()
            if not selected_wallet or selected_wallet not in self.wallet_core.wallets:
                return
                
            # 清除现有数据
            for item in tree.get_children():
                tree.delete(item)
            
            # 获取并显示交易历史
            wallet_data = self.wallet_core.wallets[selected_wallet]
            history = wallet_data.get('transaction_history', [])
            
            if not history:
                # 如果没有历史，尝试从网络获取
                def fetch_history():
                    try:
                        success = self.wallet_core.get_transaction_history_sync(selected_wallet)
                        if success:
                            dialog.after(0, update_history)
                    except Exception as e:
                        print(f"获取历史失败: {e}")
                
                threading.Thread(target=fetch_history, daemon=True).start()
                tree.insert('', tk.END, values=('正在获取交易历史...', '', '', '', ''))
                return
            
            # 填充数据
            for tx in history:
                time_str = tx['time'].strftime('%Y-%m-%d %H:%M:%S')
                tx_type = '收入' if tx['type'] == 'in' else '支出'
                amount_str = f"{tx['amount']:.6f} OCT"
                addr = tx['to'] if tx['type'] == 'out' else tx['from']
                hash_short = tx['hash'][:16] + '...'
                
                tree.insert('', tk.END, values=(time_str, tx_type, amount_str, addr, hash_short))
        
        def refresh_history():
            """刷新交易历史"""
            selected_wallet = wallet_selector.get()
            if not selected_wallet:
                return
                
            # 清除现有数据
            for item in tree.get_children():
                tree.delete(item)
            tree.insert('', tk.END, values=('正在刷新交易历史...', '', '', '', ''))
            
            def fetch_task():
                try:
                    success = self.wallet_core.get_transaction_history_sync(selected_wallet)
                    dialog.after(0, update_history)
                except Exception as e:
                    print(f"刷新历史失败: {e}")
                    dialog.after(0, lambda: tree.insert('', tk.END, values=(f'获取失败: {e}', '', '', '', '')))
            
            threading.Thread(target=fetch_task, daemon=True).start()
        
        # 绑定事件
        wallet_selector.bind('<<ComboboxSelected>>', lambda e: update_history())
        refresh_btn.config(command=refresh_history)
        
        # 初始更新
        update_history()
        
        # 关闭按钮
        close_btn = tk.Button(dialog, text="关闭", command=dialog.destroy,
                             font=('Arial', 11, 'bold'),
                             bg='#718096', fg='black',
                             relief='flat', bd=0, pady=8, width=12)
        close_btn.pack(pady=(0, 20))
    
    def clear_history(self):
        """清除历史"""
        dialog = tk.Toplevel(self.root)
        dialog.title("清除历史")
        dialog.geometry("400x200")
        dialog.configure(bg='#2d3748')
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="🗑️ 清除交易历史", font=('Arial', 16, 'bold'), 
                fg='#63b3ed', bg='#2d3748').pack(pady=20)
        
        # 钱包选择
        tk.Label(dialog, text="选择要清除历史的钱包:", font=('Arial', 12), 
                fg='#e2e8f0', bg='#2d3748').pack(anchor='w', padx=20)
        
        wallet_selector = ttk.Combobox(dialog, values=["所有钱包"] + self.wallet_core.get_wallet_list(), 
                                      state="readonly", font=('Arial', 11))
        wallet_selector.pack(padx=20, pady=(5, 20), fill=tk.X)
        wallet_selector.set(self.wallet_core.current_wallet_name or "所有钱包")
        
        def clear_selected():
            selected = wallet_selector.get()
            if not selected:
                return
                
            if selected == "所有钱包":
                if messagebox.askyesno("确认", "确定要清除所有钱包的本地交易历史吗？"):
                    for wallet_name in self.wallet_core.wallets:
                        self.wallet_core.clear_history(wallet_name)
                    messagebox.showinfo("成功", "所有钱包的本地交易历史已清除")
            else:
                if messagebox.askyesno("确认", f"确定要清除 {selected} 的本地交易历史吗？"):
                    self.wallet_core.clear_history(selected)
                    messagebox.showinfo("成功", f"{selected} 的本地交易历史已清除")
            
            dialog.destroy()
        
        # 按钮
        btn_frame = tk.Frame(dialog, bg='#2d3748')
        btn_frame.pack(pady=10)
        
        clear_btn = tk.Button(btn_frame, text="清除", font=('Arial', 12, 'bold'),
                             bg='#e53e3e', fg='white', padx=20, pady=5, command=clear_selected)
        clear_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = tk.Button(btn_frame, text="取消", font=('Arial', 12, 'bold'),
                              bg='#718096', fg='white', padx=20, pady=5, command=dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=10)
    
    def on_exit(self):
        """退出程序"""
        print("🚨 on_exit 被调用，窗口关闭事件触发")
        try:
            result = messagebox.askyesno("确认退出", "确定要退出钱包程序吗？")
            print(f"🤔 用户选择: {result}")
            if result:
                print("👋 用户确认退出，销毁窗口")
                self.root.destroy()
            else:
                print("🔄 用户取消退出")
        except Exception as e:
            print(f"💥 退出对话框异常: {e}")
            # 如果对话框异常，不要自动退出
            print("🛡️ 对话框异常，程序继续运行")
    
    def run(self):
        """运行程序"""
        print("🔧 初始化钱包...")
        # 初始化钱包
        if not self.wallet_core.load_wallets():
            messagebox.showerror("错误", "无法加载钱包文件")
            return
        
        print("📊 显示钱包信息...")
        # 显示钱包信息
        self.wallet_selector.config(values=self.wallet_core.get_wallet_list())
        self.wallet_selector.set(self.wallet_core.current_wallet_name)
        self.update_current_wallet_info()
        
        # 确保窗口在屏幕中央显示
        print("🔝 配置窗口显示...")
        self.root.withdraw()  # 先隐藏窗口
        self.root.update_idletasks()  # 更新窗口布局
        
        # 获取屏幕尺寸
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # 获取窗口尺寸
        window_width = 800
        window_height = 700
        
        # 计算中心位置
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        # 设置窗口位置和大小
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # 显示窗口
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        
        print("✅ 窗口已显示在屏幕中央")
        print("👀 窗口应该现在可见，等待用户交互...")
        print("   如果您看到窗口，请点击关闭按钮或按Ctrl+C退出")
        
        # 启动时不自动刷新余额，让用户手动点击刷新按钮
        print("💡 程序启动完成，请点击'🔄 刷新余额'按钮获取最新余额")
        
        # 确保窗口保持在前台
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        
        # 强制更新界面
        self.root.update()
        
        print("🎮 开始GUI主循环...")
        try:
            # 运行主循环
            self.root.mainloop()
        except Exception as e:
            print(f"💥 主循环异常: {e}")
        finally:
            print("👋 GUI主循环结束")

def main():
    """主函数"""
    print("🚀 启动 GUI 钱包程序...")
    
    if not os.path.exists('wallet.json'):
        print("❌ 错误：找不到 wallet.json 文件")
        return
    
    print("✅ 找到钱包配置文件")
    
    try:
        print("📱 创建GUI应用...")
        app = MultiWalletGUI()
        print("🎯 启动主循环...")
        app.run()
        print("🔚 程序正常退出")
    except Exception as e:
        print(f"💥 程序出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 