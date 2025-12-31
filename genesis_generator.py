#!/usr/bin/env python3
# genesis_generator.py - 临时低难度版（仅主网难度降低，用于快速测试全流程正式分叉需要改回正常难度）

import hashlib
import scrypt
import time
import struct
import sys
import os

PHRASE = os.getenv('PHRASE', 'Some newspaper headline that describes something that happened today').encode('utf-8')

def scrypt_hash(header):
    return scrypt.hash(header, header, 1024, 1, 1, 32)

def mine_genesis(timestamp, bits_hex='0x1e0ffff0', nonce_start=0):
    print(f"开始挖掘创世块 - 时间戳: {timestamp}")
    print(f"短语: {PHRASE.decode('utf-8')}")
    print(f"难度 bits: {bits_hex} (临时低难度用于测试)")
    print("正在搜索有效 nonce... (每10秒报告一次进度)\n")

    # Coinbase 交易（简化版，足够生成 merkle）
    script_sig = b'\x04\xff\xff\x00\x1d\x01' + bytes([len(PHRASE)]) + PHRASE
    coinbase_tx = (
        b'\x01\x00\x00\x00' +                          # version
        b'\x01' +                                      # vin count
        b'\x00'*32 + b'\xff\xff\xff\xff' +             # prevout
        bytes([len(script_sig)]) + script_sig +
        b'\xff\xff\xff\xff' +                          # sequence
        b'\x01' +                                      # vout count
        b'\x00\xf2\x05\x2a\x01\x00\x00\x00' +          # 50 coins
        b'\x43' + b'\x41' + bytes.fromhex('041184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9') + b'\xac' +
        b'\x00\x00\x00\x00'                             # locktime
    )
    tx_hash = hashlib.sha256(hashlib.sha256(coinbase_tx).digest()).digest()
    merkle_root = tx_hash[::-1]

    prev_hash = b'\x00' * 32
    version = 1
    bits = int(bits_hex, 16)
    target = bits & 0xffffff
    target <<= 8 * ((bits >> 24) - 3)

    nonce = nonce_start
    start_time = time.time()
    last_report = start_time

    while True:
        header = struct.pack("<L32s32sLLL", version, prev_hash, merkle_root, timestamp, bits, nonce)
        hash_result = scrypt_hash(header)[::-1]

        if int.from_bytes(hash_result, 'big') <= target:
            genesis_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
            merkle_hex = merkle_root.hex()
            pubkey_hex = '041184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9'
            bits_str = f"0x{bits:08x}"

            print("\n=== 挖掘成功！===\n")
            print(f"genesis hash: {genesis_hash}")
            print(f"merkle hash: {merkle_hex}")
            print(f"pubkey: {pubkey_hex}")
            print(f"time: {timestamp}")
            print(f"bits: {bits_str}")
            print(f"nonce: {nonce}")
            print(f"总用时: {time.time() - start_time:.2f} 秒")
            sys.stdout.flush()
            return

        nonce += 1

        # 每10秒报告进度
        current_time = time.time()
        if current_time - last_report >= 10:
            speed = nonce / (current_time - start_time)
            print(f"当前 nonce: {nonce:,} | 速度 ≈ {speed:,.0f} H/s | 已用时 {current_time - start_time:.0f}s")
            sys.stdout.flush()
            last_report = current_time

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ["main", "test", "regtest"]:
        print("用法: python3 genesis_generator.py [main|test|regtest]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "main":
        # 临时降低主网难度到 regtest 级别，秒挖，用于快速测试全流程
        mine_genesis(int(time.time()), '0x207fffff')
    elif mode == "test":
        # testnet 临时降低测试网难度到 regtest 级别，秒挖，用于快速测试全流程
        mine_genesis(int(time.time()), '0x207fffff')
    elif mode == "regtest":
        # regtest 本来就低难度
        mine_genesis(1296688602, '0x207fffff')



