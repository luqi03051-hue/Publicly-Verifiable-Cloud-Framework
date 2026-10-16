# 云端 Transform + 公开发布 π + 任何人可重复验证

## 1. 文件与放置

把这些文件放到与 `pv_core.py` 同一目录（它们 `import pv_core / lambda_encrypt / client_decrypt`）：

| 文件 | 谁用 | 作用 |
|---|---|---|
| `lambda_service.py` | 云端 Lambda | Encrypt；Transform + Verify 自检；发布 π；所有结果写日志 |
| `pv_publish.py` | 共用 | 公共参数、记录、PKG 签名、哈希链日志 |
| `pv_store.py` | 共用 | S3 / 本地目录两种存储（本地目录用于不上云联调与测试） |
| `export_public.py` | PKG（本地） | 签名密钥、公共参数、服务器参数、签名目录 |
| `client_request.py` | 数据用户 | 生成请求（不含 sk_id）、查日志结果、本地验证并解密 |
| `public_verify.py` | 任何人 | 单条验证 / 监控模式 |
| `tests/test_service_local.py` | 开发 | 本地端到端测试 |
| `dockerignore.example` | 构建 | 复制为 `.dockerignore`，防止密钥进镜像 |

## 2. 流程

```
PKG(本地)                       私有桶 work                     Lambda                         公开桶 public
sign-keygen / params / ──────▶ config/server_mpk.json                                          public_params.json (+PKG签名)
server-params / directory      config/tuk_t<N>.json                                            directory/<idhash>.json (PKG签名)
tkeyup ──────────────────────▶ config/pkg_sign.pub

数据所有者 ─ 明文+policy,t ──▶ inbox/x ──触发──▶ Encrypt ─────▶ bundles/<oid>.json

数据用户 ─ {oid,nonce,psk} ──▶ requests/r.json ─触发─▶ 查目录取 vk_id → TranKG → Transform → Verify自检
                                                         │ 无论成功/拒绝                 ├ published：records/<oid>__<idhash>.json (含 π)
                                                         │                              └ 一律追加 audit_log.jsonl（只含承诺，不含 ID）
                                                         └ 删除请求（不留 psk） → responses/r.json

任何人 ─ public_verify.py ◀── params + record + log        数据用户 ─ client_request.py finish：本地再验 → 用 sk_id 解密
```

日志里的 `outcome`：`published`、`denied_revoked_or_time`、`denied_policy`、`rejected_unregistered`、
`rejected_bad_directory_signature`、`rejected_bad_proof`、`rejected_no_such_object`、`rejected_no_tuk_for_t`、`error_internal`。

## 3. 部署步骤（在现有流程上增量）

**A. PKG 本地**
```bash
python export_public.py sign-keygen                               # keys/pkg_sign.key(私) + public/pkg_sign.pub
python export_public.py params --sign-key keys/pkg_sign.key       # public/public_params.json（含签名）
python export_public.py server-params                             # keys/server_mpk.json
python export_public.py directory --user keys/alice.json keys/bob.json   # public/directory/*.json
python ta_local.py tkeyup --t 1 --out keys/tuk_t1.json
aws s3 cp keys/server_mpk.json   s3://$WORK/config/server_mpk.json
aws s3 cp keys/tuk_t1.json       s3://$WORK/config/tuk_t1.json
aws s3 cp public/pkg_sign.pub    s3://$WORK/config/pkg_sign.pub
aws s3 sync public/              s3://$PUBLIC/ --exclude "*.key"
```
**不要上传** `pv_setup.json`、`pkg_sign.key`、任何 `user*.json`（含 sk_id）。`pkg_sign.pub` 要多渠道公布。

**B. 镜像**：Dockerfile 最后一行改为 `CMD ["lambda_service.handler"]`；把项目根的 `dockerignore.example` 复制为 `.dockerignore`；
重新 build → push ECR → `aws lambda update-function-code`。
环境变量：`WORK_BUCKET`、`PUBLIC_BUCKET`、可选 `DEFAULT_POLICY`、`DEFAULT_T`、`PUBLISH_BUNDLES=1`（公开密文，默认关闭）。

**C. 触发器**：work 桶两条 `ObjectCreated` 通知，前缀 `inbox/` 与 `requests/`，指向同一个函数。输出不写回这两个前缀，不会递归触发。

**D. 并发**：函数预留并发设为 1（保险）；日志追加已用 S3 条件写做乐观重试。

**E. 公开桶**：只读、开启版本控制（最好 Object Lock），前面放 CloudFront；定期把 `log_head.json` 的哈希贴到另一个渠道。

**F. IAM（Lambda 角色最小权限）**
- work：Get `inbox/* requests/* bundles/* config/*`；Put `bundles/* responses/*`；Delete `requests/*`
- public：Get/Put `records/* audit_log.jsonl log_head.json bundles/*`；Get `directory/* public_params.json`
- work 桶开 SSE-KMS，`requests/*` 只允许用户写入、Lambda 读取和删除

## 4. 使用

```bash
# 数据所有者
aws s3 cp hello.txt s3://$WORK/inbox/hello.txt --metadata policy="(A and C)",t=1
aws s3 cp s3://$WORK/responses/enc_hello.txt.json -                  # 得到 object_id

# 数据用户
python client_request.py request --user keys/alice.json --object_id <OID> --out req1.json
aws s3 cp req1.json s3://$WORK/requests/req1.json                    # 触发云端 Transform
python client_request.py check  --user keys/alice.json --request req1.json --log $URL/audit_log.jsonl
python client_request.py finish --server_mpk keys/server_mpk.json --user keys/alice.json \
       --bundle bundle.json --record $URL/records/<OID>__<idhash>.json

# 任何人
python public_verify.py --params $URL/public_params.json --record $URL/records/<…>.json \
       --pkg-pubkey <公钥hex或URL> --log $URL/audit_log.jsonl --repeat 5
# 持续监控：遍历整条日志，对每条 published 记录重放验证
python public_verify.py --params $URL/public_params.json --log $URL/audit_log.jsonl \
       --monitor --base $URL --pkg-pubkey <公钥>
```

不上云先本地联调：`python lambda_service.py --local sim --key inbox/hello.txt`（目录结构 `sim/work/…`、`sim/public/…`）。

## 5. 验证了什么、没验证什么

**已在沙箱里实际运行（编译了 PBC 与 charm）：**
- `tests/test_service_local.py` 5 项全过：正常发布并验证、本地解密、监控模式、篡改 π 与篡改 ID 被拒、
  撤销/策略不满足/未注册都不产生记录但有日志、重复投递幂等、日志被改后哈希链检查失败。
- 用真实命令行走通：`ta_local → export_public → lambda_service(--local) → client_request → public_verify`；
  并检查公开与服务器材料中不含 `msk / sk_id / psk_id_s / st`。

**没有验证（需要你在真实 AWS 上试）：**
- `S3Store`：条件写 `IfMatch/IfNoneMatch` 需要较新的 boto3，在真 S3 上的并发行为未测；旧 boto3 会退化并打印 WARN。
- 触发器配置、IAM、冷启动时间、Lambda 内存是否够（SS512 配对运算很轻，预计没问题，但未实测）。

## 6. 保证与局限

- **保证**：发布的 π 经过 Verify，任何人拿到公开数据可重复验证；`vk_id` 来自 PKG 签名目录，服务器不能编造；
  所有请求的结果（含拒绝）都在哈希链日志里，用户凭 nonce 能找到自己的那条，找不到即可举证服务器没登记。
- **局限 1**：日志里的“拒绝”本身没法被外人核实真假（比如 `denied_policy`）。验证器只能证明“发布出来的是对的”。
  被拒用户可以向 PKG 披露 nonce 申诉；PKG 对照自己的撤销列表检查 `denied_revoked_or_time`。
- **局限 2**：服务器仍可能对某个请求完全不写日志；只有请求者本人能发现（`check` 超时查不到）。要让第三方也能发现，
  需要把“请求承诺”由用户自己写到服务器无法控制的地方（例如用户侧的公开日志或区块链）。
- **局限 3**：公开记录暴露“ID 在 t 时访问了 object_id”。需要隐私的话，在 `userkg` 阶段就使用假名 ID。
- **局限 4**：PKG 公钥与公共参数哈希必须经独立渠道公布，否则验证者没有信任锚。
- **局限 5**：SS512 约 80-bit，面向长期公开审计建议迁移到 BN254 / BLS12-381。
- 请求里的 psk 靠 TLS、SSE-KMS 和处理后立即删除保护；代码不会打印它。
