#!/usr/bin/env bash
# =============================================================================
# demo_public_verify.sh —— 分阶段演示：云端 Transform + 公开发布 π + 任何人验证
# 在容器内运行（不需要 AWS，用本地目录模拟两个 S3 桶）：
#
#   cd /mnt/e/lambda_encrypt_backup
#   docker run --rm -v "$PWD/example:/ex" --entrypoint bash pv-lambda /ex/demo_public_verify.sh
#
# 想把中间文件留在本机查看：再加  -v "$PWD/demo_out:/demo"  并设置  -e DEMO=/demo
# 如果提示 $'\r' 错误（Windows 换行）：sed -i 's/\r$//' example/demo_public_verify.sh
# =============================================================================
set -euo pipefail
export PYTHONWARNINGS=ignore

SRC="${SRC:-/var/task}"            # 代码所在目录
PY="${PY:-python}"
DEMO="${DEMO:-/tmp/demo}"
cd "$SRC"
rm -rf "$DEMO/keys" "$DEMO/sim" "$DEMO"/*.json 2>/dev/null || true
mkdir -p "$DEMO/keys" "$DEMO/sim/work/config" "$DEMO/sim/work/inbox" "$DEMO/sim/work/requests" "$DEMO/sim/public"
K="$DEMO/keys"; S="$DEMO/sim"

step() { echo; echo "════════════════════════════════════════════════════════════"; echo "▶ $*"; echo "════════════════════════════════════════════════════════════"; }
ind()  { sed 's/^/    /'; }
jget() { $PY -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }

step "1/10  PKG（本地）：Setup / 用户密钥 / 时间段更新 / 撤销 bob"
$PY ta_local.py setup  --out $K/pv_setup.json | ind
$PY ta_local.py userkg --setup $K/pv_setup.json --id alice --attrs "A,C" --out $K/alice.json | ind
$PY ta_local.py userkg --setup $K/pv_setup.json --id bob   --attrs "A"   --out $K/bob.json   | ind
$PY ta_local.py tkeyup --setup $K/pv_setup.json --t 1 --out $K/tuk_t1.json | ind
$PY ta_local.py revoke --setup $K/pv_setup.json --id bob --t 2 | ind
$PY ta_local.py tkeyup --setup $K/pv_setup.json --t 2 --out $K/tuk_t2.json | ind

step "2/10  PKG 导出公开材料（签名密钥、公共参数、服务器参数、签名目录）"
$PY export_public.py sign-keygen --sk-out $K/pkg_sign.key --pk-out $S/public/pkg_sign.pub | ind
$PY export_public.py params --setup $K/pv_setup.json --out $S/public/public_params.json --sign-key $K/pkg_sign.key | ind
$PY export_public.py server-params --setup $K/pv_setup.json --out $S/work/config/server_mpk.json | ind
$PY export_public.py directory --setup $K/pv_setup.json --user $K/alice.json $K/bob.json --sign-key $K/pkg_sign.key --out-dir $S/public/directory | ind
cp $K/tuk_t1.json $K/tuk_t2.json $S/work/config/ ; cp $S/public/pkg_sign.pub $S/work/config/pkg_sign.pub
echo "  检查：上传到云端的材料里不应出现 msk / sk_id / psk_id_s / 树状态 ——"
if grep -rlE '"msk"|"sk_id"|"psk_id_s"|"st"' "$S" >/dev/null; then echo "    ✗ 发现敏感字段！"; exit 1; else echo "    ✓ 未发现"; fi

step "3/10  云端 Encrypt：上传明文，策略 (A and C)，时间段 t=1"
echo -n "hello from the cloud" > $S/work/inbox/hello.txt
echo '{"policy":"(A and C)","t":"1"}' > $S/work/inbox/hello.txt.meta.json
$PY lambda_service.py --local $S --key inbox/hello.txt | ind
OID=$(jget $S/work/responses/enc_hello.txt.json object_id); echo "  object_id = $OID"

step "4/10  alice 提交请求（只含 psk，不含 sk_id）→ 云端 TranKG + Transform + Verify 自检 + 发布 π"
$PY client_request.py request --user $K/alice.json --object_id $OID --out $DEMO/req1.json | ind
cp $DEMO/req1.json $S/work/requests/req1.json
$PY lambda_service.py --local $S --key requests/req1.json | ind
echo "  请求文件是否已被删除（不留 psk）： $( [ -e $S/work/requests/req1.json ] && echo 否 || echo 是 )"
echo "  公开桶里新增的记录："; ls $S/public/records | ind
$PY client_request.py check --user $K/alice.json --request $DEMO/req1.json --log $S/public/audit_log.jsonl | ind
REC=$S/public/$(jget $S/work/responses/req1.json record_key)

step "5/10  任何人验证（只用公开数据，重复 3 次）"
$PY public_verify.py --params $S/public/public_params.json --record $REC --pkg-pubkey $S/public/pkg_sign.pub \
    --log $S/public/audit_log.jsonl --bundle $S/work/bundles/$OID.json --repeat 3 | ind

step "6/10  alice 本地再验一次，并用自己的 sk_id 解密"
$PY client_request.py finish --server_mpk $S/work/config/server_mpk.json --user $K/alice.json \
    --bundle $S/work/bundles/$OID.json --record $REC | ind

step "7/10  篡改演示：把 π 平方后重新封印哈希 —— 验证器必须报 FAIL"
$PY - "$REC" "$DEMO/tampered.json" <<'PYEOF'
import json, sys, pv_core, pv_publish as P
from charm.toolbox.pairinggroup import PairingGroup
rec = json.load(open(sys.argv[1])); g = PairingGroup(rec["curve"])
pi = pv_core.deserialize_any(g, rec["pi"]); rec["pi"] = pv_core.serialize_any(g, pi * pi)
json.dump(P.seal_record(rec), open(sys.argv[2], "w"))
PYEOF
$PY public_verify.py --params $S/public/public_params.json --record $DEMO/tampered.json \
    --pkg-pubkey $S/public/pkg_sign.pub --repeat 1 | ind || echo "    （退出码非 0 = 验证失败，符合预期）"

step "8/10  拒绝也要留痕：bob 在 t=2 已被撤销；alice 对策略 B 没有属性"
echo -n "for t=2" > $S/work/inbox/t2.txt;  echo '{"policy":"A","t":"2"}' > $S/work/inbox/t2.txt.meta.json
$PY lambda_service.py --local $S --key inbox/t2.txt | ind
OID2=$(jget $S/work/responses/enc_t2.txt.json object_id)
echo -n "needs B" > $S/work/inbox/b.txt;   echo '{"policy":"B","t":"1"}' > $S/work/inbox/b.txt.meta.json
$PY lambda_service.py --local $S --key inbox/b.txt | ind
OID3=$(jget $S/work/responses/enc_b.txt.json object_id)
$PY client_request.py request --user $K/bob.json   --object_id $OID2 --out $DEMO/req2.json | ind
cp $DEMO/req2.json $S/work/requests/req2.json; $PY lambda_service.py --local $S --key requests/req2.json | ind
$PY client_request.py request --user $K/alice.json --object_id $OID3 --out $DEMO/req3.json | ind
cp $DEMO/req3.json $S/work/requests/req3.json; $PY lambda_service.py --local $S --key requests/req3.json | ind
echo "  bob / alice 在日志里各自查到的结果："
$PY client_request.py check --user $K/bob.json   --request $DEMO/req2.json --log $S/public/audit_log.jsonl | ind
$PY client_request.py check --user $K/alice.json --request $DEMO/req3.json --log $S/public/audit_log.jsonl | ind
echo "  公开桶里的记录数量（拒绝不产生记录，应仍为 1）： $(ls $S/public/records | wc -l)"

step "9/10  公开日志（哈希链）：只有承诺和结果，没有 ID"
$PY - "$S/public/audit_log.jsonl" <<'PYEOF' | ind
import json, sys
for l in open(sys.argv[1]):
    e = json.loads(l)
    print(f"seq={e['seq']}  outcome={e['outcome']:<24} req_commit={e['req_commit'][:12]}…  prev={e['prev'][:8]}…  hash={e['entry_sha256'][:8]}…")
PYEOF

step "10/10  监控模式：遍历整条日志，检查哈希链，并对每条已发布记录重放验证"
$PY public_verify.py --params $S/public/public_params.json --log $S/public/audit_log.jsonl \
    --monitor --base $S/public --pkg-pubkey $S/public/pkg_sign.pub | ind

echo; echo "全部演示完成。中间文件在：$DEMO"
