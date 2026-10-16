# -*- coding: utf-8 -*-
"""
public_verify.py —— 任何人 / 任何次数 / 无需任何私钥
------------------------------------------------------
输入全部是公开数据（本地路径或 http(s) URL）。两种模式：

【单条验证】
  python public_verify.py --params P --record R [--pkg-pubkey PK | --pin-mpk H]
                          [--bundle B] [--log L] [--repeat N]

【监控模式】遍历整条日志：检查哈希链，并对每条 published 记录重放密码学验证
  python public_verify.py --params P --log L --monitor --base https://…/public [--pkg-pubkey PK]

--pkg-pubkey 可以是 64 位 hex 本身，也可以是存放它的文件/URL。
退出码：0 = 全部通过；1 = 任一检查失败。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from collections import Counter

from charm.toolbox.pairinggroup import PairingGroup, pair

import pv_core
import pv_publish as P


def read_text(src: str) -> str:
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=20) as r:
            return r.read().decode("utf-8")
    with open(src, "r", encoding="utf-8") as f:
        return f.read()


def join(base: str, key: str) -> str:
    return base.rstrip("/") + "/" + key.lstrip("/")


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    return ok


def load_pubkey(arg: str) -> str:
    arg = arg.strip()
    if len(arg) == 64 and all(c in "0123456789abcdefABCDEF" for c in arg):
        return arg.lower()
    return read_text(arg).strip().lower()


# ── 参数检查 ─────────────────────────────────────────────────────────────────
def check_params(params, pkg_pk, pin) -> tuple[list, str]:
    res = []
    mpk_hash = P.sha256_hex(P.canon({"curve": params["curve"], "mpk": params["mpk"]}))
    res.append(check("public_params 自洽", mpk_hash == params["mpk_sha256"]))
    if pin:
        res.append(check("mpk 与 PKG 公布的哈希一致", mpk_hash == pin))
    if pkg_pk:
        res.append(check("public_params 带有 PKG 的有效签名",
                         "pkg_sig" in params and P.check_sig(pkg_pk, P.params_sig_msg(mpk_hash), params["pkg_sig"])))
    if not pin and not pkg_pk:
        print("  [WARN] 未提供 --pkg-pubkey / --pin-mpk：无法确认参数确实来自 PKG")
    return res, mpk_hash


def make_mpk(params):
    group = PairingGroup(params["curve"])
    mpk = pv_core.deserialize_any(group, params["mpk"])
    mpk["curve"] = params["curve"]
    mpk["H"] = pv_core.make_H(group)
    return group, mpk


# ── 记录检查 ─────────────────────────────────────────────────────────────────
def check_record(group, mpk, params, mpk_hash, rec, pkg_pk, repeat, bundle=None):
    res = []
    body = {k: v for k, v in rec.items() if k != "record_sha256"}
    rec_hash = P.sha256_hex(P.canon(body))
    res.append(check("record_sha256 自洽", rec_hash == rec.get("record_sha256")))
    res.append(check("record 引用的 mpk 一致", rec.get("mpk_sha256") == mpk_hash))

    if pkg_pk:
        res.append(check("(ID, vk_id) 带有 PKG 的有效签名",
                         bool(rec.get("vk_dir_sig")) and
                         P.check_sig(pkg_pk, P.dir_sig_msg(rec["ID"], rec["vk_id"]), rec["vk_dir_sig"])))
    else:
        print("  [WARN] 未提供 --pkg-pubkey：无法确认 vk_id 确实属于该 ID")

    if bundle is not None:
        res.append(check("record 绑定到该存储密文 (enc_sha256)",
                         P.sha256_hex(P.canon(bundle["enc"])) == rec["enc_sha256"]))
        bct = {k: bundle["enc"]["ct"][k] for k in rec["ct_pub"]}
        res.append(check("record 中 ct_pub 与存储密文一致", P.canon(bct) == P.canon(rec["ct_pub"])))

    res.append(check("Setup 约束 e(g0,k0)==e(u0,g)", pair(mpk["g0"], mpk["k0"]) == pair(mpk["u0"], mpk["g"])))

    pi = pv_core.deserialize_any(group, rec["pi"])
    vk = pv_core.deserialize_any(group, rec["vk_id"])
    ct = pv_core.deserialize_any(group, rec["ct_pub"])
    enc = pv_core.EncryptResult(t_prime=rec["t"], policy_str=rec["policy"], policy=None, hdr=None, ct=ct)

    outcomes, times = [], []
    for _ in range(repeat):
        t0 = time.perf_counter()
        outcomes.append(bool(P.quiet(pv_core.verify, mpk, enc, pi, vk, ID=rec["ID"])))
        times.append((time.perf_counter() - t0) * 1000)
    res.append(check(f"Verify x{repeat} 结果一致且通过", all(outcomes), f"avg={sum(times)/len(times):.1f} ms"))
    return res, rec_hash


# ── 日志检查 ─────────────────────────────────────────────────────────────────
def check_log(entries, rec_hash=None):
    res = []
    ok, head = P.check_chain(entries)
    res.append(check("哈希链完整", ok, f"entries={len(entries)} head={head[:16]}…"))
    if rec_hash is not None:
        res.append(check("record 已被日志收录（outcome=published）",
                         any(e.get("record_sha256") == rec_hash and e.get("outcome") == "published" for e in entries)))
    return res


def run_single(a) -> int:
    params = json.loads(read_text(a.params))
    rec = json.loads(read_text(a.record))
    pkg_pk = load_pubkey(a.pkg_pubkey) if a.pkg_pubkey else None
    results = []

    print("== 1. 参数 ==")
    r, mpk_hash = check_params(params, pkg_pk, a.pin_mpk)
    results += r
    group, mpk = make_mpk(params)

    print("== 2. 记录与密码学验证 ==")
    bundle = json.loads(read_text(a.bundle)) if a.bundle else None
    r, rec_hash = check_record(group, mpk, params, mpk_hash, rec, pkg_pk, a.repeat, bundle)
    results += r

    if a.log:
        print("== 3. 公开日志 ==")
        results += check_log(P.parse_log(read_text(a.log).encode("utf-8")), rec_hash)

    ok = all(results)
    print("== 结论:", "VERIFIED ✅" if ok else "NOT VERIFIED ❌", "==")
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump({"object_id": rec.get("object_id"), "ID": rec.get("ID"), "t": rec.get("t"),
                       "mpk_sha256": mpk_hash, "record_sha256": rec_hash, "verified": ok,
                       "repeat": a.repeat, "ts": int(time.time())}, f, indent=2)
    return 0 if ok else 1


def run_monitor(a) -> int:
    if not (a.log and a.base):
        raise SystemExit("--monitor 需要 --log 和 --base")
    params = json.loads(read_text(a.params))
    pkg_pk = load_pubkey(a.pkg_pubkey) if a.pkg_pubkey else None
    print("== 参数 ==")
    r, mpk_hash = check_params(params, pkg_pk, a.pin_mpk)
    results = list(r)
    group, mpk = make_mpk(params)

    print("== 日志 ==")
    entries = P.parse_log(read_text(a.log).encode("utf-8"))
    results += check_log(entries)
    print("  outcome 统计:", dict(Counter(e.get("outcome") for e in entries)))

    print("== 逐条重放 published 记录 ==")
    n = 0
    for e in entries:
        if e.get("outcome") != "published":
            continue
        rec = json.loads(read_text(join(a.base, e["record_key"])))
        print(f"-- seq={e['seq']} {e['record_key']}")
        ok_hash = check("record 哈希与日志一致", rec.get("record_sha256") == e.get("record_sha256"))
        r, _ = check_record(group, mpk, params, mpk_hash, rec, pkg_pk, 1)
        results += [ok_hash] + r
        n += 1
    print(f"  已重放 {n} 条")

    ok = all(results)
    print("== 监控结论:", "ALL OK ✅" if ok else "PROBLEMS FOUND ❌", "==")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="PV-SR-ABE 公开验证器")
    ap.add_argument("--params", required=True)
    ap.add_argument("--record")
    ap.add_argument("--pkg-pubkey", help="PKG 的 Ed25519 公钥（hex / 文件 / URL）")
    ap.add_argument("--pin-mpk", help="PKG 通过独立渠道公布的 mpk_sha256")
    ap.add_argument("--bundle", help="存储的密文 bundle（用于绑定 enc_sha256）")
    ap.add_argument("--log", help="哈希链日志")
    ap.add_argument("--repeat", type=int, default=3, help="重复验证次数")
    ap.add_argument("--report", help="把结果写成 JSON 报告")
    ap.add_argument("--monitor", action="store_true", help="监控模式：遍历日志并重放所有记录")
    ap.add_argument("--base", help="监控模式下公开桶的根路径/URL（用于取 records/）")
    a = ap.parse_args()
    if a.monitor:
        return run_monitor(a)
    if not a.record:
        raise SystemExit("需要 --record（或使用 --monitor）")
    return run_single(a)


if __name__ == "__main__":
    sys.exit(main())
