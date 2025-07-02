#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Octra 钱包生成器
从 wallet-gen-main 提取的核心功能

功能:
- 生成BIP39助记词
- 创建Ed25519密钥对
- 生成Octra地址
- 保存钱包文件
- 签名验证测试
"""

import secrets
import hashlib
import hmac
import base64
import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# 导入必要的加密库
try:
    from mnemonic import Mnemonic
    import nacl.signing
    import nacl.encoding
except ImportError:
    print("错误: 请安装必要的依赖包:")
    print("pip install mnemonic pynacl")
    exit(1)

# Base58字母表 (Bitcoin风格)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

class OctraWalletGenerator:
    """Octra钱包生成器类"""
    
    def __init__(self):
        self.mnemo = Mnemonic("english")
        
    def generate_entropy(self, strength: int = 128) -> bytes:
        """
        生成加密安全的随机熵
        
        Args:
            strength: 熵强度，支持128, 160, 192, 224, 256位
            
        Returns:
            bytes: 生成的熵
        """
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("熵强度必须是 128, 160, 192, 224 或 256 位")
        
        return secrets.token_bytes(strength // 8)
    
    def derive_master_key(self, seed: bytes) -> Tuple[bytes, bytes]:
        """
        使用HMAC-SHA512和"Octra seed"派生主密钥
        
        Args:
            seed: BIP39种子
            
        Returns:
            Tuple[bytes, bytes]: (主私钥, 主链码)
        """
        key = b"Octra seed"
        mac = hmac.new(key, seed, hashlib.sha512).digest()
        master_private_key = mac[:32]
        master_chain_code = mac[32:64]
        return master_private_key, master_chain_code
    
    def derive_child_key_ed25519(self, private_key: bytes, chain_code: bytes, index: int) -> Tuple[bytes, bytes]:
        """
        Ed25519的HD密钥派生
        
        Args:
            private_key: 父私钥
            chain_code: 父链码
            index: 派生索引
            
        Returns:
            Tuple[bytes, bytes]: (子私钥, 子链码)
        """
        if index >= 0x80000000:
            # 硬化派生
            data = b'\x00' + private_key + index.to_bytes(4, 'big')
        else:
            # 非硬化派生
            signing_key = nacl.signing.SigningKey(private_key)
            public_key = signing_key.verify_key.encode()
            data = public_key + index.to_bytes(4, 'big')
        
        mac = hmac.new(chain_code, data, hashlib.sha512).digest()
        child_private_key = mac[:32]
        child_chain_code = mac[32:64]
        return child_private_key, child_chain_code
    
    def derive_path(self, seed: bytes, path: List[int]) -> Tuple[bytes, bytes]:
        """
        从种子按路径派生密钥
        
        Args:
            seed: BIP39种子
            path: 派生路径列表
            
        Returns:
            Tuple[bytes, bytes]: (派生私钥, 链码)
        """
        master_private_key, master_chain_code = self.derive_master_key(seed)
        key = master_private_key
        chain = master_chain_code
        
        for index in path:
            key, chain = self.derive_child_key_ed25519(key, chain, index)
        
        return key, chain
    
    def base58_encode(self, data: bytes) -> str:
        """
        Base58编码
        
        Args:
            data: 要编码的字节数据
            
        Returns:
            str: Base58编码的字符串
        """
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
        """
        创建Octra地址
        格式: oct + Base58(SHA256(pubkey))
        
        Args:
            public_key: Ed25519公钥
            
        Returns:
            str: Octra地址
        """
        hash_digest = hashlib.sha256(public_key).digest()
        base58_hash = self.base58_encode(hash_digest)
        return "oct" + base58_hash
    
    def verify_address_format(self, address: str) -> bool:
        """
        验证地址格式
        
        Args:
            address: 要验证的地址
            
        Returns:
            bool: 地址格式是否正确
        """
        if not address.startswith("oct"):
            return False
        if len(address) != 47:  # oct + 44字符的base58
            return False
        
        base58_part = address[3:]
        for char in base58_part:
            if char not in BASE58_ALPHABET:
                return False
        
        return True
    
    def get_network_type_name(self, network_type: int) -> str:
        """
        获取网络类型名称
        
        Args:
            network_type: 网络类型编号
            
        Returns:
            str: 网络类型名称
        """
        network_names = {
            0: "MainCoin",
            1: f"SubCoin {network_type}",
            2: f"Contract {network_type}",
            3: f"Subnet {network_type}",
            4: f"Account {network_type}"
        }
        return network_names.get(network_type, f"Unknown {network_type}")
    
    def derive_for_network(self, seed: bytes, network_type: int = 0, network: int = 0, 
                          contract: int = 0, account: int = 0, index: int = 0,
                          token: int = 0, subnet: int = 0) -> Dict:
        """
        为特定网络派生钱包
        
        Args:
            seed: BIP39种子
            network_type: 网络类型
            network: 网络编号
            contract: 合约编号
            account: 账户编号
            index: 索引编号
            token: 代币编号
            subnet: 子网编号
            
        Returns:
            Dict: 派生的网络钱包信息
        """
        coin_type = 0 if network_type == 0 else network_type
        
        # 构建派生路径: m/345'/coin_type'/network'/contract'/account'/token'/subnet'/index
        full_path = [
            0x80000000 + 345,  # Purpose (hardened)
            0x80000000 + coin_type,  # Coin type (hardened)
            0x80000000 + network,  # Network (hardened)
            0x80000000 + contract,  # Contract (hardened)
            0x80000000 + account,  # Account (hardened)
            0x80000000 + token,  # Token (hardened)
            0x80000000 + subnet,  # Subnet (hardened)
            index  # Index (non-hardened)
        ]
        
        derived_key, derived_chain = self.derive_path(seed, full_path)
        
        # 生成Ed25519密钥对
        signing_key = nacl.signing.SigningKey(derived_key)
        public_key = signing_key.verify_key.encode()
        
        # 生成地址
        address = self.create_octra_address(public_key)
        
        return {
            "private_key": derived_key,
            "chain_code": derived_chain,
            "public_key": public_key,
            "address": address,
            "path": full_path,
            "network_type_name": self.get_network_type_name(network_type),
            "network": network,
            "contract": contract,
            "account": account,
            "index": index
        }
    
    def generate_wallet(self, entropy_strength: int = 128) -> Dict:
        """
        生成完整的Octra钱包
        
        Args:
            entropy_strength: 熵强度，默认128位
            
        Returns:
            Dict: 完整的钱包数据
        """
        print("🔄 生成钱包中...")
        
        # 1. 生成熵
        print("📊 生成熵...")
        entropy = self.generate_entropy(entropy_strength)
        
        # 2. 创建助记词
        print("📝 创建助记词...")
        mnemonic = self.mnemo.to_mnemonic(entropy)
        mnemonic_words = mnemonic.split(" ")
        
        # 3. 从助记词派生种子
        print("🌱 从助记词派生种子...")
        seed = self.mnemo.to_seed(mnemonic)
        
        # 4. 派生主密钥
        print("🔑 派生主密钥...")
        master_private_key, master_chain_code = self.derive_master_key(seed)
        
        # 5. 创建Ed25519密钥对
        print("🔐 创建Ed25519密钥对...")
        signing_key = nacl.signing.SigningKey(master_private_key)
        private_key_raw = signing_key.encode()[:32]  # 只取前32字节作为私钥
        public_key_raw = signing_key.verify_key.encode()
        
        # 6. 生成Octra地址
        print("🏠 生成Octra地址...")
        address = self.create_octra_address(public_key_raw)
        
        # 7. 验证地址格式
        if not self.verify_address_format(address):
            raise ValueError("生成的地址格式无效")
        print("✅ 地址格式验证通过")
        
        # 8. 签名测试
        print("🔐 测试签名功能...")
        test_message = '{"from":"test","to":"test","amount":"1000000","nonce":1}'
        test_signature = signing_key.sign(test_message.encode()).signature
        
        # 验证签名
        try:
            verify_key = nacl.signing.VerifyKey(public_key_raw)
            verify_key.verify(test_message.encode(), test_signature)
            signature_valid = True
            print("✅ 签名测试通过")
        except Exception:
            signature_valid = False
            print("❌ 签名测试失败")
        
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
        
        print("🎉 钱包生成完成!")
        return wallet_data
    
    def save_wallet(self, wallet_data: Dict, filename: Optional[str] = None, 
                   format_type: str = "txt") -> str:
        """
        保存钱包到文件
        
        Args:
            wallet_data: 钱包数据字典
            filename: 自定义文件名，None则自动生成
            format_type: 保存格式，支持 "txt", "json"
            
        Returns:
            str: 保存的文件路径
        """
        # 生成文件名
        if filename is None:
            timestamp = int(datetime.now().timestamp())
            address_suffix = wallet_data["address"][-8:]  # 取地址最后8位
            filename = f"octra_wallet_{address_suffix}_{timestamp}.{format_type}"
        
        if format_type.lower() == "json":
            # JSON格式保存
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(wallet_data, f, indent=2, ensure_ascii=False)
        else:
            # 文本格式保存
            content = self._format_wallet_text(wallet_data)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
        
        print(f"💾 钱包已保存到: {filename}")
        return filename
    
    def _format_wallet_text(self, wallet_data: Dict) -> str:
        """
        格式化钱包数据为文本格式
        
        Args:
            wallet_data: 钱包数据字典
            
        Returns:
            str: 格式化的文本内容
        """
        content = f"""OCTRA WALLET
{"=" * 50}

⚠️  SECURITY WARNING: KEEP THIS FILE SECURE AND NEVER SHARE YOUR PRIVATE KEY

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Address Format: oct + Base58(SHA256(pubkey))
Signature Algorithm: Ed25519
Derivation: BIP39-compatible (PBKDF2-HMAC-SHA512, 2048 iterations)

助记词 (Mnemonic):
{' '.join(wallet_data['mnemonic'])}

地址 (Address):
{wallet_data['address']}

私钥 (Private Key):
Hex: {wallet_data['private_key_hex']}
Base64: {wallet_data['private_key_b64']}

公钥 (Public Key):
Hex: {wallet_data['public_key_hex']}
Base64: {wallet_data['public_key_b64']}

技术细节 (Technical Details):
Entropy: {wallet_data['entropy_hex']}
Seed: {wallet_data['seed_hex']}
Master Chain Code: {wallet_data['master_chain_hex']}

签名测试 (Signature Test):
Test Message: {wallet_data['test_message']}
Test Signature: {wallet_data['test_signature']}
Signature Valid: {'✅ 通过' if wallet_data['signature_valid'] else '❌ 失败'}

⚠️  WARNING: 
- 请妥善保管您的助记词和私钥
- 不要将此文件存储在云服务上
- 不要截图或复制到不安全的地方
- 丢失助记词将无法恢复钱包
"""
        return content
    
    def import_from_mnemonic(self, mnemonic: str) -> Dict:
        """
        从助记词导入钱包
        
        Args:
            mnemonic: 助记词字符串
            
        Returns:
            Dict: 钱包数据
        """
        print("📥 从助记词导入钱包...")
        
        # 验证助记词
        if not self.mnemo.check(mnemonic):
            raise ValueError("无效的助记词")
        
        # 派生种子
        print("🌱 从助记词派生种子...")
        seed = self.mnemo.to_seed(mnemonic)
        
        # 派生主密钥
        print("🔑 派生主密钥...")
        master_private_key, master_chain_code = self.derive_master_key(seed)
        
        # 创建密钥对
        print("🔐 创建密钥对...")
        signing_key = nacl.signing.SigningKey(master_private_key)
        private_key_raw = signing_key.encode()[:32]
        public_key_raw = signing_key.verify_key.encode()
        
        # 生成地址
        print("🏠 生成地址...")
        address = self.create_octra_address(public_key_raw)
        
        # 签名测试
        test_message = '{"from":"test","to":"test","amount":"1000000","nonce":1}'
        test_signature = signing_key.sign(test_message.encode()).signature
        
        try:
            verify_key = nacl.signing.VerifyKey(public_key_raw)
            verify_key.verify(test_message.encode(), test_signature)
            signature_valid = True
        except Exception:
            signature_valid = False
        
        wallet_data = {
            "mnemonic": mnemonic.split(),
            "seed_hex": seed.hex(),
            "master_chain_hex": master_chain_code.hex(),
            "private_key_hex": private_key_raw.hex(),
            "public_key_hex": public_key_raw.hex(),
            "private_key_b64": base64.b64encode(private_key_raw).decode(),
            "public_key_b64": base64.b64encode(public_key_raw).decode(),
            "address": address,
            "test_message": test_message,
            "test_signature": base64.b64encode(test_signature).decode(),
            "signature_valid": signature_valid,
            "imported_at": datetime.now().isoformat()
        }
        
        print("✅ 钱包导入完成!")
        return wallet_data

def main():
    """主函数 - 命令行界面"""
    parser = argparse.ArgumentParser(description="Octra 钱包生成器")
    parser.add_argument("--generate", "-g", action="store_true", help="生成新钱包")
    parser.add_argument("--import", "-i", dest="import_mnemonic", 
                       help="从助记词导入钱包")
    parser.add_argument("--output", "-o", help="输出文件名")
    parser.add_argument("--format", "-f", choices=["txt", "json"], 
                       default="txt", help="输出格式 (默认: txt)")
    parser.add_argument("--strength", "-s", type=int, choices=[128, 160, 192, 224, 256],
                       default=128, help="熵强度 (默认: 128)")
    
    args = parser.parse_args()
    
    generator = OctraWalletGenerator()
    
    try:
        if args.generate:
            # 生成新钱包
            print("🚀 开始生成新的Octra钱包...")
            wallet_data = generator.generate_wallet(args.strength)
            
            # 显示钱包信息
            print("\n" + "=" * 60)
            print("📋 钱包信息预览:")
            print(f"🏠 地址: {wallet_data['address']}")
            print(f"📝 助记词: {' '.join(wallet_data['mnemonic'])}")
            print(f"🔐 私钥: {wallet_data['private_key_hex'][:16]}...")
            print(f"🔑 公钥: {wallet_data['public_key_hex'][:16]}...")
            print("=" * 60)
            
            # 保存钱包
            filename = generator.save_wallet(wallet_data, args.output, args.format)
            print(f"\n✅ 钱包已成功保存!")
            print(f"📁 文件位置: {os.path.abspath(filename)}")
            
        elif args.import_mnemonic:
            # 从助记词导入钱包
            print("📥 从助记词导入钱包...")
            wallet_data = generator.import_from_mnemonic(args.import_mnemonic)
            
            # 显示钱包信息
            print("\n" + "=" * 60)
            print("📋 导入的钱包信息:")
            print(f"🏠 地址: {wallet_data['address']}")
            print(f"📝 助记词: {' '.join(wallet_data['mnemonic'])}")
            print(f"🔐 私钥: {wallet_data['private_key_hex'][:16]}...")
            print("=" * 60)
            
            # 保存钱包
            filename = generator.save_wallet(wallet_data, args.output, args.format)
            print(f"\n✅ 钱包已成功保存!")
            print(f"📁 文件位置: {os.path.abspath(filename)}")
            
        else:
            # 交互式模式
            print("🎯 Octra 钱包生成器")
            print("=" * 30)
            print("1. 生成新钱包")
            print("2. 从助记词导入钱包") 
            print("3. 退出")
            
            choice = input("\n请选择操作 (1-3): ").strip()
            
            if choice == "1":
                wallet_data = generator.generate_wallet()
                print(f"\n🏠 地址: {wallet_data['address']}")
                print(f"📝 助记词: {' '.join(wallet_data['mnemonic'])}")
                
                save = input("\n是否保存钱包? (y/n): ").strip().lower()
                if save in ['y', 'yes', '是']:
                    filename = generator.save_wallet(wallet_data, format_type=args.format)
                    print(f"📁 已保存到: {os.path.abspath(filename)}")
                    
            elif choice == "2":
                mnemonic = input("请输入助记词: ").strip()
                wallet_data = generator.import_from_mnemonic(mnemonic)
                print(f"\n🏠 地址: {wallet_data['address']}")
                
                save = input("\n是否保存钱包? (y/n): ").strip().lower()
                if save in ['y', 'yes', '是']:
                    filename = generator.save_wallet(wallet_data, format_type=args.format)
                    print(f"📁 已保存到: {os.path.abspath(filename)}")
                    
            elif choice == "3":
                print("👋 再见!")
                return
            else:
                print("❌ 无效的选择")
                
    except Exception as e:
        print(f"❌ 错误: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 