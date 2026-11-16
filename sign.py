# -*- coding: utf-8 -*-
"""verified.json → allowlist.json (Ed25519 서명 봉투). GitHub Actions 가 실행한다.

개인키는 저장소 Secret `ALLOWLIST_SIGNING_KEY`(PEM 전체)에만 있다. 이 스크립트는 앱(core/allowlist.py)과
같은 형식 규칙으로 verified.json 을 검사한 뒤 서명한다. 검사에 실패하면 서명하지 않는다.
"""
import base64
import json
import os
import re
import sys

from cryptography.hazmat.primitives import serialization

TAG = re.compile(r"^v?\d+(\.\d+){1,3}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def check(data: bytes) -> dict:
    doc = json.loads(data.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("serial"), int):
        sys.exit("verified.json: schema 1 과 정수 serial 이 필요합니다")
    for tag, commit in (doc.get("engine") or {}).items():
        if not (TAG.match(tag) and isinstance(commit, str) and COMMIT.match(commit)):
            sys.exit("verified.json: engine 항목 형식 오류: %r" % tag)
    for t in doc.get("revoked") or []:
        if not (isinstance(t, str) and TAG.match(t)):
            sys.exit("verified.json: revoked 항목 형식 오류: %r" % t)
    return doc


def main():
    pem = os.environ.get("ALLOWLIST_SIGNING_KEY", "").encode()
    if not pem.strip():
        sys.exit("Secret ALLOWLIST_SIGNING_KEY 가 없습니다")
    key = serialization.load_pem_private_key(pem, password=None)
    data = open("verified.json", "rb").read()
    doc = check(data)
    prev = None
    if os.path.exists("allowlist.json"):
        try:
            prev = json.loads(base64.b64decode(json.load(open("allowlist.json"))["payload"]))["serial"]
        except Exception:  # noqa: BLE001
            prev = None
    if prev is not None and doc["serial"] <= prev and data != base64.b64decode(json.load(open("allowlist.json"))["payload"]):
        sys.exit("serial 을 올리세요(지금 %d, 이전 %d) — 앱은 이전보다 크지 않은 새 목록을 거부합니다" % (doc["serial"], prev))
    sig = base64.b64encode(key.sign(data)).decode()
    env = json.dumps({"payload": base64.b64encode(data).decode("ascii"), "sig": sig}, indent=1) + "\n"
    open("allowlist.json", "w", encoding="ascii", newline="\n").write(env)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("signed serial %d, engines %s, revoked %s, public key %s" % (
        doc["serial"], ", ".join(sorted(doc.get("engine") or {})) or "-",
        ", ".join(doc.get("revoked") or []) or "-", base64.b64encode(pub).decode()))


if __name__ == "__main__":
    main()
