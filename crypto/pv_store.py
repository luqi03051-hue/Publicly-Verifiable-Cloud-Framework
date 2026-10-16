# -*- coding: utf-8 -*-
"""
pv_store.py —— 两个“区域”的存储抽象
  work   : 私有桶（inbox/ requests/ bundles/ config/ responses/）
  public : 只读公开桶（public_params.json、directory/、records/、audit_log.jsonl、log_head.json）

S3Store  : 真实 AWS（Lambda 内使用）
DirStore : 本地目录模拟，便于不部署就跑通全流程和测试
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, Optional, Tuple


class Store:
    def get(self, area: str, key: str) -> Optional[bytes]: ...
    def put(self, area: str, key: str, data: bytes, ctype: str = "application/json") -> None: ...
    def delete(self, area: str, key: str) -> None: ...
    def exists(self, area: str, key: str) -> bool: ...
    def meta(self, area: str, key: str) -> Dict[str, str]: ...
    def get_etag(self, area: str, key: str) -> Tuple[Optional[bytes], Optional[str]]: ...
    def put_if_match(self, area: str, key: str, data: bytes, etag: Optional[str]) -> bool:
        """etag=None 表示“必须尚不存在”。成功返回 True，被他人抢先写入返回 False。"""
        ...


class DirStore(Store):
    """本地目录模拟：root/<area>/<key>；对象元数据用 <key>.meta.json 旁路文件模拟。"""

    def __init__(self, root: str):
        self.root = root

    def _p(self, area, key):
        p = os.path.join(self.root, area, key)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def get(self, area, key):
        p = self._p(area, key)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return f.read()

    def put(self, area, key, data, ctype="application/json"):
        with open(self._p(area, key), "wb") as f:
            f.write(data)

    def delete(self, area, key):
        p = self._p(area, key)
        if os.path.exists(p):
            os.remove(p)

    def exists(self, area, key):
        return os.path.exists(self._p(area, key))

    def meta(self, area, key):
        p = self._p(area, key) + ".meta.json"
        if not os.path.exists(p):
            return {}
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_etag(self, area, key):
        d = self.get(area, key)
        return d, (hashlib.md5(d).hexdigest() if d is not None else None)

    def put_if_match(self, area, key, data, etag):
        _, cur = self.get_etag(area, key)
        if cur != etag:
            return False
        self.put(area, key, data)
        return True


class S3Store(Store):
    def __init__(self, work_bucket: str, public_bucket: str):
        import boto3
        self.s3 = boto3.client("s3")
        self.buckets = {"work": work_bucket, "public": public_bucket}

    def _b(self, area):
        return self.buckets[area]

    def get(self, area, key):
        from botocore.exceptions import ClientError
        try:
            return self.s3.get_object(Bucket=self._b(area), Key=key)["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise

    def put(self, area, key, data, ctype="application/json"):
        self.s3.put_object(Bucket=self._b(area), Key=key, Body=data, ContentType=ctype)

    def delete(self, area, key):
        self.s3.delete_object(Bucket=self._b(area), Key=key)

    def exists(self, area, key):
        from botocore.exceptions import ClientError
        try:
            self.s3.head_object(Bucket=self._b(area), Key=key)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def meta(self, area, key):
        return self.s3.head_object(Bucket=self._b(area), Key=key).get("Metadata", {})

    def get_etag(self, area, key):
        from botocore.exceptions import ClientError
        try:
            r = self.s3.get_object(Bucket=self._b(area), Key=key)
            return r["Body"].read(), r["ETag"]
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None, None
            raise

    def put_if_match(self, area, key, data, etag):
        """用 S3 条件写（IfMatch / IfNoneMatch）做乐观并发控制；需要较新的 boto3。"""
        from botocore.exceptions import ClientError, ParamValidationError
        kw = dict(Bucket=self._b(area), Key=key, Body=data, ContentType="application/json")
        if etag is None:
            kw["IfNoneMatch"] = "*"
        else:
            kw["IfMatch"] = etag
        try:
            self.s3.put_object(**kw)
            return True
        except ParamValidationError:
            # boto3 太旧不支持条件写：退化为普通写。此时必须把 Lambda 预留并发设为 1，
            # 否则并发调用可能互相覆盖日志。
            print("[WARN] boto3 lacks conditional writes; set reserved concurrency = 1")
            self.s3.put_object(Bucket=self._b(area), Key=key, Body=data, ContentType="application/json")
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict", "412", "409"):
                return False
            raise
