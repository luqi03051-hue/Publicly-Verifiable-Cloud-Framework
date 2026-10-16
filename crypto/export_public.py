# -*- coding: utf-8 -*-
"""
export_public.py —— PKG 在本地运行：生成/导出所有“可以公开”的材料
--------------------------------------------------------------------
  sign-keygen    生成 PKG 的 Ed25519 签名密钥对（私钥只留本地，公钥公布）
  params         pv_setup.json -> public_params.json   验证者用：g,g0,k0,u0 + mpk_sha256 (+ PKG 签名)
  server-params  pv_setup.json -> server_mpk.json      服务器用：完整 mpk（全是公开量）
  directory      user.json -> directory/<idhash>.json  PKG 签名的 (ID, vk_id) 目录条目（不含任何私钥）
  record         本地离线生成一条验证记录（线上由 lambda_service.py 生成）

所有输出都不含 msk、sk_id、psk、PKG 树状态(gx)。
"""
from __future__ import annotations

import argparse
import json
import os

import pv_core
import pv_publish as P


def _write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _read_hex(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def cmd_sign_keygen(a):
    sk, pk = P.gen_sign_keypair()
    _write(a.sk_out, sk + "\n")
    _write(a.pk_out, pk + "\n")
    try:
        os.chmod(a.sk_out, 0o600)
    except OSError:
        pass
    print(f"[PKG] signing key -> {a.sk_out}  (仅本地保存，不要上传)")
    print(f"[PKG] public key  -> {a.pk_out}  (上传到 work/config/pkg_sign.pub，并多渠道公布)")


def cmd_params(a):
    group, mpk, _msk, _st = pv_core.load_setup_json(a.setup)   # msk 读入后即丢弃，不写出
    blob = P.public_params_blob(group, mpk, _read_hex(a.sign_key) if a.sign_key else None)
    pv_core.save_json(a.out, blob)
    print(f"[PKG] params -> {a.out}")
    print(f"[PKG] mpk_sha256 = {blob['mpk_sha256']}")
    if not a.sign_key:
        print("[WARN] 未签名：验证者只能用 --pin-mpk 钉住哈希")


def cmd_server_params(a):
    group, mpk, _msk, _st = pv_core.load_setup_json(a.setup)
    pv_core.save_json(a.out, P.server_mpk_blob(group, mpk))
    print(f"[PKG] server mpk -> {a.out}  (上传到 work/config/server_mpk.json)")


def cmd_directory(a):
    group, _mpk, _msk, _st = pv_core.load_setup_json(a.setup)
    sk = _read_hex(a.sign_key)
    for path in a.user:
        user = pv_core.load_user(group, pv_core.load_json(path))   # 只取 ID 与 vk_id
        entry = P.directory_entry(group, user.ID, user.vk_id, sk)
        out = os.path.join(a.out_dir, f"{P.id_hash(user.ID)}.json")
        _write(out, json.dumps(entry, ensure_ascii=False, indent=2))
        print(f"[PKG] directory entry for {user.ID} -> {out}")


def cmd_record(a):
    group, mpk, _msk, _st = pv_core.load_setup_json(a.setup)
    user = pv_core.load_user(group, pv_core.load_json(a.user))
    up = pv_core.load_tuk(group, pv_core.load_json(a.tuk))
    with open(os.path.join(a.store_dir, f"{a.object_id}.json"), "r", encoding="utf-8") as f:
        bundle = json.load(f)
    enc = pv_core.load_encrypt(group, bundle["enc"])
    entry = pv_core.load_json(os.path.join(a.directory_dir, f"{P.id_hash(user.ID)}.json"))

    tk = pv_core.trankg(mpk, user.psk_id_s, up.tuk_t, t=enc.t_prime)
    if tk is None:
        raise SystemExit("TranKG 返回 ⊥（用户被撤销或时间段不匹配），不生成记录")
    tr = pv_core.transform(mpk, enc, tk.tk_id_t_s, ID=user.ID)
    if tr is None or not tr.ok:
        raise SystemExit("Transform 失败（策略不满足），不生成记录")
    if not P.quiet(pv_core.verify, mpk, enc, tr.pi, user.vk_id, ID=user.ID):
        raise SystemExit("自检 Verify 未通过，拒绝发布")

    rec = P.build_record(group, mpk, enc, bundle["enc"], a.object_id, user.ID,
                         entry["vk_id"], entry["sig"], tr.pi)
    pv_core.save_json(a.out, rec)
    print(f"[PKG] record -> {a.out}  (record_sha256={rec['record_sha256'][:16]}…)")

    if a.log:
        data = open(a.log, "rb").read() if os.path.exists(a.log) else b""
        entries = P.parse_log(data)
        commit = P.req_commit(a.object_id, user.ID, "offline")
        e = P.next_log_entry(entries[-1] if entries else None,
                             {"type": "result", "req_commit": commit, "object_id": a.object_id,
                              "outcome": "published", "record_key": os.path.basename(a.out),
                              "record_sha256": rec["record_sha256"]})
        os.makedirs(os.path.dirname(a.log) or ".", exist_ok=True)
        with open(a.log, "ab") as f:
            f.write((json.dumps(e, ensure_ascii=False) + "\n").encode("utf-8"))
        print(f"[PKG] log seq={e['seq']} head={e['entry_sha256']}")


def main():
    ap = argparse.ArgumentParser(description="导出 PV-SR-ABE 公开材料")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("sign-keygen"); k.set_defaults(fn=cmd_sign_keygen)
    k.add_argument("--sk-out", default="keys/pkg_sign.key"); k.add_argument("--pk-out", default="public/pkg_sign.pub")

    p = sub.add_parser("params"); p.set_defaults(fn=cmd_params)
    p.add_argument("--setup", default="keys/pv_setup.json"); p.add_argument("--out", default="public/public_params.json")
    p.add_argument("--sign-key", default=None, help="PKG 签名私钥文件（建议提供）")

    s = sub.add_parser("server-params"); s.set_defaults(fn=cmd_server_params)
    s.add_argument("--setup", default="keys/pv_setup.json"); s.add_argument("--out", default="keys/server_mpk.json")

    d = sub.add_parser("directory"); d.set_defaults(fn=cmd_directory)
    d.add_argument("--setup", default="keys/pv_setup.json")
    d.add_argument("--user", nargs="+", required=True, help="一个或多个 user.json")
    d.add_argument("--sign-key", default="keys/pkg_sign.key"); d.add_argument("--out-dir", default="public/directory")

    r = sub.add_parser("record"); r.set_defaults(fn=cmd_record)
    r.add_argument("--setup", default="keys/pv_setup.json")
    r.add_argument("--user", required=True); r.add_argument("--tuk", required=True)
    r.add_argument("--object_id", required=True); r.add_argument("--store_dir", default="keys/store")
    r.add_argument("--directory-dir", dest="directory_dir", default="public/directory")
    r.add_argument("--out", required=True); r.add_argument("--log", default="public/audit_log.jsonl")

    a = ap.parse_args(); a.fn(a)


if __name__ == "__main__":
    main()
