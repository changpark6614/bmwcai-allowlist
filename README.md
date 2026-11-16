# bmwcai-allowlist

BMW Custom App Installer 가 읽는 **서명된 SSH 엔진 허용 목록**입니다.
앱은 `allowlist.json`(내용 + Ed25519 서명)을 받아, 앱에 박힌 공개키로 서명이 맞을 때만 사용합니다.
서명은 이 저장소의 GitHub Actions 가 자동으로 합니다 — 개인키는 저장소 Secret 에만 있습니다.

## 처음 한 번 설정
1. 이 저장소를 **Public** 으로 만듭니다(앱이 로그인 없이 읽어야 함).
2. Settings ▶ Secrets and variables ▶ Actions ▶ **New repository secret**
   - Name: `ALLOWLIST_SIGNING_KEY`
   - Secret: 전달받은 개인키 PEM 파일 내용 전체(`-----BEGIN PRIVATE KEY-----` 부터 끝까지)
   - 저장 후 PC 에 있는 PEM 파일은 삭제합니다.
3. Settings ▶ Actions ▶ General ▶ Workflow permissions ▶ **Read and write permissions** 선택.
4. 계정에 2단계 인증(2FA)을 켜 둡니다(이 계정 = 서명 권한).

## 새 엔진 버전 허용하기 (웹에서 끝)
1. 업스트림(cauliflowermossgrape/idrive7-8-ssh-root) 새 태그를 실차에서 Flash + Enable 확인
2. GitHub 웹에서 `verified.json` 편집: `engine` 에 `"태그": "커밋 40자리"` 추가, **`serial` 을 1 올림**
3. Commit → Actions 가 서명해서 `allowlist.json` 을 자동 커밋(1~2분). Actions 탭에서 초록불 확인
4. 사용자 앱은 다음 'SSH 엔진 새 버전 확인' 때 반영(재설치 불필요)

## 문제 버전 막기
`revoked` 에 태그를 넣고 serial 을 올려 커밋 — 앱에 내장된 목록에 있어도 차단됩니다.

## 새 앱 버전 알림
`app.latest`, `app.url`, `app.note` 를 고치고 serial 을 올려 커밋하면 앱이 안내합니다(자동 설치 없음).

## 주의
- `allowlist.json` 은 손으로 고치지 마세요(서명이 깨짐). 항상 `verified.json` 만 고칩니다.
- serial 은 절대 내리지 마세요. 앱은 한 번 받은 serial 보다 작은 목록을 거부합니다.
