# -*- coding: utf-8 -*-
"""
pv_publish.py —— 公开验证扩展的共享逻辑（服务器、PKG 导出工具、验证器共用）

只处理“公开数据”：公共参数、验证记录、PKG 签名目录、哈希链日志条目。
本模块不接触 msk / sk_id。
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import time
from typing import Any, Dict, Optional, Tuple

from charm.toolbox.pairinggroup import PairingGroup
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import pv_core

# Verify 只需要的 mpk 分量 / 密文分量
PUBLIC_MPK_KEYS = ["g", "g0", "k0", "u0"]
# 服务器做 Encrypt / TranKG / Transform 需要完整 mpk（全部是公开量，不含 msk 与 PKG 树状态）
SERVER_MPK_KEYS = ["g", "g0", "k0", "u0", "u1", "h0", "h1", "u", "h", "v", "w", "k",
                   "egg_alpha", "eu0g_beta"]
PUBLIC_CT_KEYS = ["C0", "Cg", "Ck0", "CH"]

GENESIS = "0" * 64


# ── 基础工具 ──────────────────────────────────────────────────────────────────
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def id_hash(ID: str) -> str:
    return sha256_hex(ID.encode("utf-8"))[:16]


def req_commit(object_id: str, ID: str, nonce: str) -> str:
    """请求承诺：带用户随机数，外人无法由它反推出 ID，但用户可以凭 nonce 证明“这是我的请求”。"""
    return sha256_hex(canon({"object_id": object_id, "ID": ID, "nonce": nonce}))


def quiet(fn, *a, **kw):
    """屏蔽 pv_core 里的调试打印。"""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


# ── Ed25519 签名（PKG 用来签公共参数 与 (ID, vk_id) 目录）──────────────────────
def gen_sign_keypair() -> Tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    sk_hex = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption()).hex()
    pk_hex = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return sk_hex, pk_hex


def sign(sk_hex: str, msg: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex)).sign(msg).hex()


def check_sig(pk_hex: str, msg: bytes, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def params_sig_msg(mpk_sha256: str) -> bytes:
    return canon({"type": "params", "mpk_sha256": mpk_sha256})


def dir_sig_msg(ID: str, vk_id_ser) -> bytes:
    return canon({"type": "dir", "ID": ID, "vk_id": vk_id_ser})


# ── 参数 ─────────────────────────────────────────────────────────────────────
def public_params_blob(group: PairingGroup, mpk: Dict[str, Any], sign_sk_hex: Optional[str] = None):
    pub = pv_core.serialize_any(group, {k: mpk[k] for k in PUBLIC_MPK_KEYS})
    blob = {"scheme": "PV-SR-ABE", "curve": mpk["curve"], "mpk": pub}
    blob["mpk_sha256"] = sha256_hex(canon({"curve": blob["curve"], "mpk": pub}))
    if sign_sk_hex:
        blob["pkg_sig"] = sign(sign_sk_hex, params_sig_msg(blob["mpk_sha256"]))
    return blob


def server_mpk_blob(group: PairingGroup, mpk: Dict[str, Any]) -> Dict[str, Any]:
    return {"curve": mpk["curve"],
            "mpk": pv_core.serialize_any(group, {k: mpk[k] for k in SERVER_MPK_KEYS})}


def load_server_mpk(blob: Dict[str, Any]) -> Tuple[PairingGroup, Dict[str, Any]]:
    group = PairingGroup(blob["curve"])
    mpk = pv_core.deserialize_any(group, blob["mpk"])
    mpk["curve"] = blob["curve"]
    mpk["H"] = pv_core.make_H(group)
    return group, mpk


# ── PKG 签名目录：每个用户一条 {ID, vk_id, sig} ─────────────────────────────────
def directory_entry(group: PairingGroup, ID: str, vk_id, sign_sk_hex: str) -> Dict[str, Any]:
    vk_ser = pv_core.serialize_any(group, vk_id)
    return {"ID": ID, "vk_id": vk_ser, "sig": sign(sign_sk_hex, dir_sig_msg(ID, vk_ser))}


# ── 验证记录 ──────────────────────────────────────────────────────────────────
def seal_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    rec = {k: v for k, v in rec.items() if k != "record_sha256"}
    rec["record_sha256"] = sha256_hex(canon(rec))
    return rec


def build_record(group, mpk, enc, enc_blob: Dict[str, Any], object_id: str,
                 ID: str, vk_id_ser, vk_dir_sig: Optional[str], pi) -> Dict[str, Any]:
    rec = {
        "scheme": "PV-SR-ABE",
        "version": 2,
        "curve": mpk["curve"],
        "object_id": object_id,
        "ID": ID,
        "t": enc.t_prime,
        "policy": enc.policy_str,
        "mpk_sha256": public_params_blob(group, mpk)["mpk_sha256"],
        "enc_sha256": sha256_hex(canon(enc_blob)),       # 把 π 绑定到存储里的那份密文
        "vk_id": vk_id_ser,                              # 与 PKG 目录中的完全一致
        "vk_dir_sig": vk_dir_sig,                        # PKG 对 (ID, vk_id) 的签名
        "pi": pv_core.serialize_any(group, pi),
        "ct_pub": pv_core.serialize_any(group, {k: enc.ct[k] for k in PUBLIC_CT_KEYS}),
    }
    return seal_record(rec)


# ── 哈希链日志 ────────────────────────────────────────────────────────────────
def next_log_entry(last: Optional[Dict[str, Any]], fields: Dict[str, Any]) -> Dict[str, Any]:
    entry = {"seq": 0 if last is None else last["seq"] + 1,
             "ts": int(time.time()),
             "prev": GENESIS if last is None else last["entry_sha256"],
             **fields}
    entry["entry_sha256"] = sha256_hex(canon(entry))
    return entry


def parse_log(data: Optional[bytes]):
    if not data:
        return []
    return [json.loads(l) for l in data.decode("utf-8").splitlines() if l.strip()]


def check_chain(entries) -> Tuple[bool, str]:
    prev, ok = GENESIS, True
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items() if k != "entry_sha256"}
        ok &= (e.get("seq") == i and e.get("prev") == prev and sha256_hex(canon(body)) == e.get("entry_sha256"))
        prev = e.get("entry_sha256", "")
    return ok, prev
