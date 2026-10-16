"""
本地端到端测试：不需要 AWS，用 DirStore 模拟两个桶，直接调用 lambda_service.handler。
放置：与 pv_core.py 同目录的 tests/ 下，运行  pytest -q tests/test_service_local.py

覆盖：
  1 正常流程：加密 -> 请求 -> 云端 Transform+Verify -> 发布 π -> 公开验证器通过 -> 客户端本地解密
  2 监控模式：遍历日志并重放所有 published 记录
  3 篡改 π（重新封印哈希）/ 篡改 ID（重新封印哈希）-> 验证器必须拒绝
  4 被撤销用户 / 策略不满足 / 未注册用户 -> 无记录，但日志里有对应 outcome
  5 重复投递同一请求 -> 日志不重复；请求文件被删除；日志篡改 -> 哈希链检查失败
"""
import json
import sys
import urllib.parse
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup

import client_request
import lambda_service as svc
import pv_core
import pv_publish as P
import public_verify
from pv_store import DirStore


def ev(key):
    return {"Records": [{"s3": {"object": {"key": urllib.parse.quote_plus(key)}}}]}


def put_json(store, area, key, obj):
    store.put(area, key, json.dumps(obj).encode())


class Env:
    pass


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sim")
    e = Env()
    e.tmp, e.store = tmp, DirStore(str(tmp))
    res = pv_core.setup(depth=4)
    e.res, e.group = res, PairingGroup(res.curve)
    e.sk, e.pk = P.gen_sign_keypair()

    e.alice = pv_core.userkg(res.mpk, res.msk, res.st, ID="alice", S=["A", "C"])
    e.bob = pv_core.userkg(res.mpk, res.msk, res.st, ID="bob", S=["A"])
    e.carol = pv_core.userkg(res.mpk, res.msk, res.st, ID="carol", S=["A"])   # 不登记到目录
    pv_core.revoke(res.st, "bob", 2)

    s, g = e.store, e.group
    put_json(s, "work", "config/server_mpk.json", P.server_mpk_blob(g, res.mpk))
    s.put("work", "config/pkg_sign.pub", e.pk.encode())
    for t in (1, 2):
        put_json(s, "work", f"config/tuk_t{t}.json", pv_core.dump_tuk(g, pv_core.tkeyup(res.mpk, res.msk, res.st, t=t)))
    put_json(s, "public", "public_params.json", P.public_params_blob(g, res.mpk, e.sk))
    for u in (e.alice, e.bob):
        put_json(s, "public", f"directory/{P.id_hash(u.ID)}.json", P.directory_entry(g, u.ID, u.vk_id, e.sk))

    # 用户文件（含 sk_id，只在“用户本机”）
    for name, u in (("alice", e.alice), ("bob", e.bob), ("carol", e.carol)):
        (tmp / f"{name}.json").write_text(json.dumps(pv_core.dump_user(g, u)))
    e.nonce = 0
    return e


def encrypt(env, name, policy, t, text=b"hello world"):
    env.store.put("work", f"inbox/{name}", text)
    (env.tmp / "work" / "inbox" / f"{name}.meta.json").write_text(json.dumps({"policy": policy, "t": str(t)}))
    out = json.loads(svc.handler(ev(f"inbox/{name}"), store=env.store)["body"])[0]
    return out["object_id"]


def request(env, user, oid, req_id, nonce=None):
    u = pv_core.dump_user(env.group, user)
    env.nonce += 1
    put_json(env.store, "work", f"requests/{req_id}.json",
             {"object_id": oid, "nonce": nonce or f"nonce-{env.nonce:08d}", "psk_id_s": u["psk_id_s"]})
    return json.loads(svc.handler(ev(f"requests/{req_id}.json"), store=env.store)["body"])[0]


def log_entries(env):
    return P.parse_log(env.store.get("public", "audit_log.jsonl"))


def verify_cli(monkeypatch, env, rec_path, extra=()):
    pub = env.tmp / "public"
    monkeypatch.setattr(sys, "argv", ["public_verify.py", "--params", str(pub / "public_params.json"),
                                      "--record", str(rec_path), "--pkg-pubkey", env.pk,
                                      "--log", str(pub / "audit_log.jsonl"), "--repeat", "2", *extra])
    return public_verify.main()


def test_1_publish_verify_and_decrypt(env, monkeypatch, capsys):
    oid = encrypt(env, "a.txt", "A", 1, b"secret message")
    r = request(env, env.alice, oid, "r1")
    assert r["ok"] and r["outcome"] == "published", r
    assert not env.store.exists("work", "requests/r1.json")             # psk 不留存

    rec_path = env.tmp / "public" / r["record_key"]
    bundle_path = env.tmp / "work" / "bundles" / f"{oid}.json"
    assert verify_cli(monkeypatch, env, rec_path, ["--bundle", str(bundle_path)]) == 0   # 任何人可验证

    capsys.readouterr()
    client_request.cmd_finish(Namespace(server_mpk=str(env.tmp / "work/config/server_mpk.json"),
                                        user=str(env.tmp / "alice.json"),
                                        bundle=str(bundle_path), record=str(rec_path)))
    assert "secret message" in capsys.readouterr().out                   # 用户本地解密成功
    env.oid1, env.rec1 = oid, rec_path


def test_2_monitor_mode(env, monkeypatch):
    pub = env.tmp / "public"
    monkeypatch.setattr(sys, "argv", ["public_verify.py", "--params", str(pub / "public_params.json"),
                                      "--log", str(pub / "audit_log.jsonl"), "--monitor",
                                      "--base", str(pub), "--pkg-pubkey", env.pk])
    assert public_verify.main() == 0


def test_3_tampering_is_rejected(env, monkeypatch):
    rec = json.loads(env.rec1.read_text())

    bad_pi = dict(rec)                                                   # 篡改 π，哈希重新封印
    pi = pv_core.deserialize_any(env.group, rec["pi"])
    bad_pi["pi"] = pv_core.serialize_any(env.group, pi * pi)
    p1 = env.tmp / "bad_pi.json"; p1.write_text(json.dumps(P.seal_record(bad_pi)))
    assert verify_cli(monkeypatch, env, p1) == 1

    bad_id = dict(rec, ID="mallory")                                     # 换成别人的 ID，签名对不上
    p2 = env.tmp / "bad_id.json"; p2.write_text(json.dumps(P.seal_record(bad_id)))
    assert verify_cli(monkeypatch, env, p2) == 1

    assert verify_cli(monkeypatch, env, env.rec1) == 0                   # 原记录依旧通过


def test_4_denials_are_logged_not_silent(env):
    n0 = len(log_entries(env))

    oid2 = encrypt(env, "b.txt", "A", 2)
    r = request(env, env.bob, oid2, "r2")                                # bob 在 t=2 被撤销
    assert not r["ok"] and r["outcome"] == "denied_revoked_or_time"

    oid3 = encrypt(env, "c.txt", "B", 1)
    r = request(env, env.alice, oid3, "r3")                              # alice 没有属性 B
    assert not r["ok"] and r["outcome"] == "denied_policy"

    r = request(env, env.carol, env.oid1, "r4")                          # carol 未注册
    assert not r["ok"] and r["outcome"] == "rejected_unregistered"

    new = log_entries(env)[n0:]
    assert [e["outcome"] for e in new] == ["denied_revoked_or_time", "denied_policy", "rejected_unregistered"]
    assert all("ID" not in e and "record_sha256" not in e for e in new)  # 日志不泄露 ID，拒绝不产生记录
    records = [p.name for p in (env.tmp / "public" / "records").iterdir()]
    assert records == [f"{env.oid1}__{P.id_hash('alice')}.json"]         # 只有 test_1 那一条，拒绝不产生记录


def test_5_idempotent_and_chain(env, monkeypatch):
    oid = encrypt(env, "d.txt", "A", 1)
    request(env, env.alice, oid, "r5", nonce="fixed-nonce-0001")
    n = len(log_entries(env))
    request(env, env.alice, oid, "r5b", nonce="fixed-nonce-0001")        # 同一请求重复投递
    assert len(log_entries(env)) == n

    # 用户可凭 nonce 在日志里找到自己的结果
    (env.tmp / "req_check.json").write_text(json.dumps({"object_id": oid, "nonce": "fixed-nonce-0001"}))
    client_request.cmd_check(Namespace(user=str(env.tmp / "alice.json"),
                                       request=str(env.tmp / "req_check.json"),
                                       log=str(env.tmp / "public" / "audit_log.jsonl")))

    ok, _ = P.check_chain(log_entries(env))
    assert ok
    path = env.tmp / "public" / "audit_log.jsonl"                        # 篡改历史一条 -> 链断裂
    lines = path.read_text().splitlines()
    e0 = json.loads(lines[0]); e0["outcome"] = "denied_policy"; lines[0] = json.dumps(e0)
    path.write_text("\n".join(lines) + "\n")
    ok, _ = P.check_chain(log_entries(env))
    assert not ok
    assert verify_cli(monkeypatch, env, env.rec1) == 1                   # 验证器也能发现
