# SuddenAttack 로컬 캡처 프록시 사용법

게임 클라이언트 ↔ 실제 서버 사이에 로컬 TCP 중계를 두고, 양방향
원문과 (키 확정 후) 복호화 결과를 로그로 남긴다.

```
suddenattack.exe ──> 127.0.0.1:12000 (sa_proxy.py) ──> 175.207.21.11:12000 (게임 서버)
                     │  원문 그대로 전달(pass-through)
                     ├─ logs/<session>/c2s.bin, s2c.bin     원문 스트림
                     ├─ logs/<session>/events.jsonl          연결/청크/패킷 이벤트
                     ├─ logs/<session>/packets.log           hexdump+복호화시도+문자열
                     └─ logs/<session>/strings.log           평문 문자열만 모은 로그
```

## 1. 실행

**Node판 (본 머신에서 즉시 실행 가능 — selftest 통과 완료):**

```bat
cd H:\SA_Analysis\scripts\py
node sa-proxy.js --listen 127.0.0.1:12000 --upstream 175.207.21.11:12000
node sa-proxy.js --selftest        (파이프라인 검증)
```

**Python판 (Python 3.8+ 설치 후, 동일 기능):**

```bat
cd H:\SA_Analysis\scripts\py
python sa_proxy.py --listen 127.0.0.1:12000 --upstream 175.207.21.11:12000
python sa_net_crypto.py            (암호 알고리즘 셀프테스트+KAT)
```

- `--framing u16` 이 기본. 패킷 길이 접두사 규격은 아직 와이어 확인 전
  [추정] 이며, 비정상 길이 감지 시 해당 방향은 자동으로 raw 청크로 기록된다.
  첫 캡처를 보고 u16/u32/u16h/u32h/raw 중 선택하면 된다.

## 2. 클라이언트를 프록시로 보내기

ngm:// 실행 URL 의 `-passarg` 첫 토큰이 서버 IP 이다. 이것만 127.0.0.1 로
바꿔 실행한다 (토큰 등 나머지 인자는 그대로 서버로 전달되므로 로그인 유지).

```powershell
# ngm URL 을 클립보드에 복사한 뒤:
powershell -ExecutionPolicy Bypass -File H:\SA_Analysis\scripts\py\launch-via-proxy.ps1
```

`launch-via-proxy.ps1` 은 URL 을 디코딩해 passarg IP 만 치환하고
suddenattack.exe 를 실행한다. 토큰을 파일로 저장하지 않는다.

수동 실행 템플릿 (ngm 인자가 exe 커맨드라인으로 전달된다고 가정 [추정]):

```bat
"H:\Program Files\Nexon\SuddenAttack\suddenattack.exe" -mode:launch -game:94227 -passarg:"127.0.0.1 12000 1 -1 <USERID>" -token:"<NP11 토큰>" -insign_token:"{""webtoken"":"""",""gid"":""""}" -a2sk:"act:<A2SK>" -position:"GameWeb|https://sa.nexon.com/main/index.aspx" -architectureplatform:"none" -timestamp:<TS>
```

## 3. 로그 파일

| 파일 | 내용 |
|---|---|
| `c2s.bin` / `s2c.bin` | 클라이언트→서버 / 서버→클라이언트 원문 바이트 (그대로 병합) |
| `events.jsonl` | 연결 수립/종료, 청크 도착(길이·오프셋), 프레이밍 경고 |
| `packets.log` | 패킷별 hexdump + XXTEA 복호화 시도 + ASCII/UTF-16LE 문자열 |
| `strings.log` | 문자열만 시간순 (방향/오프셋 포함) |
| `meta.json` | 설정 스냅샷 |

## 4. 복호화 현황 (2026-10-18, REA session 28 확정)

- **패킷 난독화(CStreamCryptor_v1) — 완전 해독, 자기기술적**:
  헤더 8바이트 `{rand, 태그, rand, 키32(15비트 rand), rand}` + 페이로드
  롤링 XOR → 전체 리버스 → u16 체크섬. **키가 패킷 안에 포함**되어 있어
  프록시가 키 없이 복호 가능. 두 프록시 모두 프레이밍된 각 패킷에 대해
  자동 복호를 시도하고 `packets.log` 에 `DEOBF v1` 섹션으로 남긴다.
- **XTEA-32 고정키 `"156def789023abc4"`** (cshell.dll 0x180d5ef00):
  8바이트 블록 → 대문자 헥스 16자 + `"SA"` 래퍼. 로그인 비밀번호 등
  값 난독화용 [추론]. `sa_net_crypto.py` 에 구현 완료(KAT 포함).
- 남은 미확정: u16 체크섬 함수(0x181272bc0, session 29), v1 태그바이트
  값(0x181273720, session 29), 이 난독화가 실제 12000 포트 와이어에
  그대로 쓰이는지(호출자 xrefs 대기). 프록시는 검증 없이 구조만 맞으면
  복호를 시도하므로 첫 실캡처에서 바로 확인된다.
- 과거 기록 정정: 세션 27 의 "XXTEA" 식별은 오류. 실제로는 64비트
  블록 표준 XTEA.

## 5. 주의사항

- ngm 토큰은 짧은 수명 — 캡처마다 웹에서 새 실행 URL 을 받아야 할 수 있음.
- 로그에는 계정/세션 정보가 평문으로 남을 수 있다 → `logs/` 는
  .gitignore 처리됨(커밋·업로드 금지).
- 트래픽 중계 자체는 클라이언트 프로세스를 건드리지 않지만, 서버측
  이상 감지로 계정 제재를 받을 가능성은 있다. 본인 계정·본인 판단.
- 서버 목록이 프로토콜 안에서 갱신되어 두 번째 접속(월드 서버 등)이
  다른 IP:포트로 직접 연결될 수 있다 — 그 경우 해당 포트으로 프록시
  인스턴스를 추가로 띄우고 passarg 를 다시 치환해야 한다.
