# -*- coding: utf-8 -*-
"""
lambda_service.py —— 真正在云端执行 PV-SR-ABE 的 Lambda 入口
=============================================================
同一个函数按 S3 前缀处理两类触发：

  work/inbox/<file>        数据所有者上传明文（对象元数据 policy、t）
      -> Encrypt：AES-256-GCM + ABE 包裹会话密钥 -> work/bundles/<oid>.json

  work/requests/<id>.json  数据用户的转换请求 {object_id, nonce, psk_id_s}（绝无 sk_id）
      -> 查 PKG 签名目录取 vk_id -> TranKG -> Transform -> Verify(自检)
      -> 成功：发布 public/records/<oid>__<idhash>.json（含 π）
      -> 无论成功或拒绝：向 public/audit_log.jsonl 追加一条“结果”（哈希链）
      -> 处理完立即删除请求（不留 psk）

环境变量：WORK_BUCKET, PUBLIC_BUCKET, [DEFAULT_POLICY], [DEFAULT_T], [PUBLISH_BUNDLES=1]

work 桶需要预置：
  config/server_mpk.json   (export_public.py server-params)
  config/tuk_t<N>.json     (ta_local.py tkeyup 的输出)
  config/pkg_sign.pub      (PKG 的 Ed25519 公钥，hex)
public 桶需要预置：
  public_params.json、directory/<idhash>.json（export_public.py params / directory）

本地联调（无需 AWS）：
  python lambda_service.py --local sim --key inbox/hello.txt
  python lambda_service.py --local sim --key requests/req1.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
import uuid
from typing import Any, Dict, Tuple

from charm.toolbox.pairinggroup import GT

import pv_core
import pv_publish as P
from lambda_encrypt import _aes_gcm_encrypt, _kdf        # 复用现有的 KDF / AES-GCM 封装
from pv_store import DirStore, S3Store, Store

OID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _j(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")


def _load_server_mpk(store: Store):
    raw = store.get("work", "config/server_mpk.json")
    if raw is None:
        raise RuntimeError("missing work/config/server_mpk.json (run export_public.py server-params)")
    return P.load_server_mpk(json.loads(raw))


# ── ① Encrypt ────────────────────────────────────────────────────────────────
def do_encrypt(store: Store, key: str) -> Dict[str, Any]:
    group, mpk = _load_server_mpk(store)
    meta = store.meta("work", key)
    policy = meta.get("policy") or os.environ.get("DEFAULT_POLICY")
    t = int(meta.get("t") or os.environ.get("DEFAULT_T", "1"))
    if not policy:
        raise RuntimeError("no policy: set object metadata 'policy' or env DEFAULT_POLICY")
    plaintext = store.get("work", key)

    key_gt = group.random(GT)
    enc = pv_core.encrypt_by_policy(mpk, policy_str=policy, t_prime=t, msg=key_gt)
    aes = _aes_gcm_encrypt(_kdf(group, key_gt), plaintext)

    oid = str(uuid.uuid4())
    bundle = {"scheme": "PV-SR-ABE", "curve": mpk["curve"],
              "enc": pv_core.dump_encrypt(group, enc), "aes": aes}
    store.put("work", f"bundles/{oid}.json", _j(bundle))
    if os.environ.get("PUBLISH_BUNDLES", "0") == "1":     # 默认不公开密文，由数据所有者决定
        store.put("public", f"bundles/{oid}.json", _j(bundle))

    base = os.path.basename(key)
    store.put("work", f"responses/enc_{base}.json",
              _j({"ok": True, "object_id": oid, "policy": policy, "t": t}))
    print(f"[ENC] {key} -> object_id={oid} policy={policy!r} t={t}")
    return {"op": "encrypt", "object_id": oid}


# ── ② 哈希链日志（乐观并发 + 按 req_commit 幂等）─────────────────────────────
def _append_result(store: Store, fields: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    commit = fields["req_commit"]
    for _ in range(8):
        data, etag = store.get_etag("public", "audit_log.jsonl")
        entries = P.parse_log(data)
        for e in entries:                                   # S3 事件可能重复投递：已记录就直接返回
            if e.get("req_commit") == commit:
                return e, False
        entry = P.next_log_entry(entries[-1] if entries else None, fields)
        new = (data or b"") + (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
        if store.put_if_match("public", "audit_log.jsonl", new, etag):
            store.put("public", "log_head.json",
                      _j({"seq": entry["seq"], "entry_sha256": entry["entry_sha256"], "ts": entry["ts"]}))
            return entry, True
    raise RuntimeError("audit log contention: too many retries")


# ── ③ Transform + Verify + 发布 ──────────────────────────────────────────────
def do_transform(store: Store, key: str) -> Dict[str, Any]:
    req_id = os.path.basename(key)
    if req_id.endswith(".json"):
        req_id = req_id[:-5]
    resp_key = f"responses/{req_id}.json"

    def respond(ok: bool, **kw):
        store.put("work", resp_key, _j({"ok": ok, **kw}))
        return {"op": "transform", "request": req_id, "ok": ok, **kw}

    try:
        # —— 解析请求：失败时拿不到 ID，无法生成承诺，只能给请求者一个错误响应 ——
        try:
            req = json.loads(store.get("work", key))
            oid = req["object_id"]
            nonce = str(req["nonce"])
            if not OID_RE.match(oid) or not (8 <= len(nonce) <= 128):
                raise ValueError("bad fields")
            group, mpk = _load_server_mpk(store)
            psk = pv_core.deserialize_any(group, req["psk_id_s"])
            ID = psk["ID"]
        except Exception as e:
            print(f"[ERROR] malformed request {key}: {e!r}")
            return respond(False, outcome="malformed_request")

        commit = P.req_commit(oid, ID, nonce)

        def done(outcome: str, **extra):
            """所有结果（含拒绝）都写进公开日志；日志里只有承诺，没有 ID。"""
            entry, _ = _append_result(store, {"type": "result", "req_commit": commit,
                                              "object_id": oid, "outcome": outcome, **extra})
            print(f"[TRANSFORM] {oid} -> {outcome} (log seq={entry['seq']})")
            return respond(outcome == "published", outcome=outcome, req_commit=commit,
                           log_seq=entry["seq"], **extra)

        try:
            raw_bundle = store.get("work", f"bundles/{oid}.json")
            if raw_bundle is None:
                return done("rejected_no_such_object")
            bundle = json.loads(raw_bundle)
            enc = pv_core.load_encrypt(group, bundle["enc"])

            raw_tuk = store.get("work", f"config/tuk_t{enc.t_prime}.json")
            if raw_tuk is None:
                return done("rejected_no_tuk_for_t")
            tuk = pv_core.load_tuk(group, json.loads(raw_tuk))

            # —— 用户必须在 PKG 签名目录里；vk_id 取自目录而不是请求 ——
            raw_pk = store.get("work", "config/pkg_sign.pub")
            if raw_pk is None:
                raise RuntimeError("missing work/config/pkg_sign.pub")
            raw_dir = store.get("public", f"directory/{P.id_hash(ID)}.json")
            if raw_dir is None:
                return done("rejected_unregistered")
            entry = json.loads(raw_dir)
            if entry.get("ID") != ID or not P.check_sig(raw_pk.decode().strip(),
                                                         P.dir_sig_msg(ID, entry["vk_id"]), entry["sig"]):
                return done("rejected_bad_directory_signature")
            vk_id = pv_core.deserialize_any(group, entry["vk_id"])

            # TranKG：用户被撤销（或 tuk 与密文时间段不匹配）时返回 ⊥
            tk = P.quiet(pv_core.trankg, mpk, psk, tuk.tuk_t, t=enc.t_prime)
            if tk is None:
                return done("denied_revoked_or_time")

            # Transform：策略不满足时失败
            tr = P.quiet(pv_core.transform, mpk, enc, tk.tk_id_t_s, ID=ID)
            if tr is None or not tr.ok:
                return done("denied_policy")

            # 发布前服务器先自检：公开的 π 一定通过 Verify
            if not P.quiet(pv_core.verify, mpk, enc, tr.pi, vk_id, ID=ID):
                return done("rejected_bad_proof")

            rec = P.build_record(group, mpk, enc, bundle["enc"], oid, ID,
                                 entry["vk_id"], entry["sig"], tr.pi)
            rkey = f"records/{oid}__{P.id_hash(ID)}.json"
            store.put("public", rkey, _j(rec))               # 先写记录，再写日志：崩溃重试是安全的
            return done("published", record_key=rkey, record_sha256=rec["record_sha256"])

        except Exception as e:
            print(f"[ERROR] {oid}: {e!r}")
            return done("error_internal")

    finally:
        store.delete("work", key)                            # 无论成败都删除请求，不保留 psk


# ── 入口 ─────────────────────────────────────────────────────────────────────
def handler(event, context=None, store: Store = None):
    store = store or S3Store(os.environ["WORK_BUCKET"], os.environ["PUBLIC_BUCKET"])
    results = []
    for rec in event.get("Records", []):
        key = urllib.parse.unquote_plus(rec["s3"]["object"]["key"])
        if key.startswith("inbox/"):
            results.append(do_encrypt(store, key))
        elif key.startswith("requests/"):
            results.append(do_transform(store, key))
        else:
            results.append({"skipped": key})
    return {"statusCode": 200, "body": json.dumps(results)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", required=True, help="本地模拟目录（含 work/ public/）")
    ap.add_argument("--key", required=True, help="inbox/... 或 requests/...")
    a = ap.parse_args()
    ev = {"Records": [{"s3": {"object": {"key": urllib.parse.quote_plus(a.key)}}}]}
    print(handler(ev, store=DirStore(a.local)))
