# -*- coding: utf-8 -*-
"""
client_request.py —— 数据用户端

  request : 从 user.json 里只摘出 psk_id_s，加上随机 nonce，生成请求文件（绝不含 sk_id）
  check   : 在公开日志里查自己的请求结果（published / denied_* / rejected_*）；
            超时仍查不到 = 服务器没有登记，可据此举证
  finish  : 取回服务器发布的 record -> 本地 Verify -> 用 sk_id 本地解密

  python client_request.py request --user keys/alice.json --object_id <OID> --out req1.json
  aws s3 cp req1.json s3://<work-bucket>/requests/req1.json          # 触发 Lambda
  python client_request.py check   --user keys/alice.json --request req1.json --log URL/audit_log.jsonl
  python client_request.py finish  --server_mpk keys/server_mpk.json --user keys/alice.json \
        --bundle bundle.json --record URL/records/<OID>__<idhash>.json
"""
from __future__ import annotations

import argparse
import json
import secrets
import urllib.request

import pv_core
import pv_publish as P
from client_decrypt import _aes_gcm_decrypt
from lambda_encrypt import _kdf


def _read(src: str) -> str:
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=20) as r:
            return r.read().decode("utf-8")
    with open(src, encoding="utf-8") as f:
        return f.read()


def cmd_request(a):
    u = json.loads(_read(a.user))
    req = {"object_id": a.object_id, "nonce": secrets.token_hex(16), "psk_id_s": u["psk_id_s"]}
    assert "sk_id" not in req
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(req, f)
    print(f"[CLIENT] request -> {a.out}（已剔除 sk_id）")
    print(f"[CLIENT] req_commit = {P.req_commit(a.object_id, u['ID'], req['nonce'])}  （用它在公开日志里找结果）")


def cmd_check(a):
    u = json.loads(_read(a.user))
    req = json.loads(_read(a.request))
    commit = P.req_commit(req["object_id"], u["ID"], req["nonce"])
    entries = P.parse_log(_read(a.log).encode("utf-8"))
    ok, _ = P.check_chain(entries)
    if not ok:
        raise SystemExit("[CLIENT] 日志哈希链不完整，日志本身不可信")
    hit = [e for e in entries if e.get("req_commit") == commit]
    if not hit:
        raise SystemExit("[CLIENT] 日志中没有你的请求结果（若已超时，说明服务器未登记）")
    e = hit[0]
    print(f"[CLIENT] 结果: {e['outcome']}  (log seq={e['seq']})" +
          (f"  record={e['record_key']}" if e.get("record_key") else ""))


def cmd_finish(a):
    group, mpk = P.load_server_mpk(json.loads(_read(a.server_mpk)))
    user = pv_core.load_user(group, json.loads(_read(a.user)))
    bundle = json.loads(_read(a.bundle))
    rec = json.loads(_read(a.record))
    enc = pv_core.load_encrypt(group, bundle["enc"])
    pi = pv_core.deserialize_any(group, rec["pi"])

    if rec["ID"] != user.ID:
        raise SystemExit("[CLIENT] record 不属于该用户")
    if P.sha256_hex(P.canon(bundle["enc"])) != rec["enc_sha256"]:
        raise SystemExit("[CLIENT] record 对应的不是这份密文")
    if not P.quiet(pv_core.verify, mpk, enc, pi, user.vk_id, ID=user.ID):
        raise SystemExit("[CLIENT] Verify FAILED —— 服务器返回的 π 不正确，已中止（可公开举证）")
    print("[CLIENT] Verify PASSED")
    key_gt = pv_core.decrypt(mpk, user.sk_id, pi, enc.hdr, ID=user.ID)
    pt = _aes_gcm_decrypt(_kdf(group, key_gt), bundle["aes"]["nonce"], bundle["aes"]["ct"])
    print("[CLIENT] Plaintext:", pt.decode("utf-8", errors="replace"))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request"); r.set_defaults(fn=cmd_request)
    r.add_argument("--user", required=True); r.add_argument("--object_id", required=True); r.add_argument("--out", required=True)
    c = sub.add_parser("check"); c.set_defaults(fn=cmd_check)
    c.add_argument("--user", required=True); c.add_argument("--request", required=True); c.add_argument("--log", required=True)
    f = sub.add_parser("finish"); f.set_defaults(fn=cmd_finish)
    f.add_argument("--server_mpk", required=True); f.add_argument("--user", required=True)
    f.add_argument("--bundle", required=True); f.add_argument("--record", required=True)
    a = ap.parse_args(); a.fn(a)


if __name__ == "__main__":
    main()
