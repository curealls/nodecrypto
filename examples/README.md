# 워크플로우 및 데이터 예제 (examples)

NodeCrypto 워크플로우 템플릿(`.ncw`), 암호화 프로토콜 샘플 및 테스트 벡터 데이터를 보관한다.

## kat/

내부 규격이 정한 의미론의 자체 테스트 벡터(KAT)를 보관한다. 형식은 항목마다 입력과 기대 결과를 JSON으로 적는 방식이다(아래 각 폴더 설명 참조).

- `kat/bytes-ops/<연산>.json`: `bytesOps` 연산별 벡터. 한 파일은 `{ "op", "args", "result" | "error" }` 항목의 JSON 배열이다. 러너는 `products/engine/tests/kat/bytes_ops.test.ts`이다.
- `kat/builtin-script/<분류>.json`: 내장 스크립트 해석기 벡터(`examples`, `int`, `bytes`, `control`, `static-errors`, `limits`). 한 항목은 `{ "name", "ports", "inputs", "script", "outputs" | "error" }`이며 `error`는 정적 오류이면 첫 진단의 `code`, 실행 오류이면 오류 코드이다. 러너는 `products/engine/tests/kat/builtin_script.test.ts`이다.

## workflows/

`.ncw` 워크플로우 파일과, 인공지능이 쓰는 초안(`drafts/`)을 보관한다. "파일 > 열기"로 열어 실행하거나 CLI(`nodecrypto run`)로 실행한다. 초안 형식은 `nodecrypto guide`가 출력하는 안내서를 따른다.

### 검증된 예제

공개 시험 벡터로 검증한 예제이다. 이름마다 파일 셋이 한 벌이다.

- `drafts/<이름>.json`: 초안 원본. 인공지능이 따라 쓸 예시이다. 앱에서 배치를 손본 예제(`did-auth-client`, `did-auth-keygen`, `mlkem-roundtrip`, `cmac-subkey`, `sha256-link`)는 `.ncw`가 원본이므로 초안을 두지 않는다.
- `<이름>.ncw`: 초안을 `nodecrypto expand`로 펼친 패키지. 테스트가 초안을 펼친 결과와 같은지 확인한다.
- `<이름>.expect.json`: `{ "source", "inputs", "outputs" }`. `source`는 시험 벡터 출처(절 번호까지), `inputs`와 `outputs`는 CLI 값 표기이다(`cli-spec.md` §5). Workflow Input 포트의 `defaultValue`는 `inputs`와 같은 값이어야 한다(앱의 실행 대화상자가 이 값으로 채워지며, 테스트가 확인한다).

```
nodecrypto run examples/workflows/hmac-sha256.ncw --inputs '{"Key":"4a656665","Data":"7768617420646f2079612077616e7420666f72206e6f7468696e673f"}' --expect '{"MAC":"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"}'
```

| 이름 | 내용 | 출처 |
| --- | --- | --- |
| `aes-gcm` | AES-128-GCM 암호화와 태그 | RFC 7714 §16.1.1 |
| `aes-gcm-named` | `aes-gcm`과 같은 시험 벡터, AES 노드의 고정 포트에 역할 이름(`portNames`) | RFC 7714 §16.1.1 |
| `hmac-sha256` | HMAC-SHA-256 | RFC 4231 §4.3 |
| `hkdf-sha256` | HKDF-SHA-256 (L=42) | RFC 5869 §A.1 |
| `pbkdf2-sha256` | PBKDF2-HMAC-SHA-256 (c=1, dkLen=64) | RFC 7914 §11 |
| `x25519-ecdh` | X25519 공유 비밀 | RFC 7748 §6.1 |
| `ed25519-sign` | Ed25519 서명 | RFC 8032 §7.1 TEST 2 |
| `cmac-aes` | AES-CMAC (40바이트) | RFC 4493 §4 Example 3 |
| `x25519-hkdf` | X25519 공유 비밀 → HKDF로 세션 키 | RFC 7748 §6.1, HKDF 출력은 Node `crypto.hkdfSync`로 교차 확인 |
| `x25519-hkdf-named` | `x25519-hkdf`와 같은 시험 벡터, 두 노드의 고정 포트에 역할 이름(`portNames`) | `x25519-hkdf`와 같음 |
| `seed-ecb` | SEED-128 ECB 한 블록 | RFC 4269 부록 B.4, KISA SEED 128 Test Vector |
| `rsa-components-decrypt` | N, e, d → RSA Key Encoder(`Private`, p와 q는 자동 복원) → RSA Decrypt(OAEP, SHA-256)로 암호문을 복호화해 평문 19바이트 확인. 폐기용 1024비트 시험 키 | 독립 구현 대조(Node `crypto`/OpenSSL이 같은 키로 암호화·복호화), 새로 생성한 시험 전용 키라 공개 시험 벡터 없음 |
| `sha256-link` | SHA-256 다이제스트를 Link 노드를 거쳐 출력으로 전달(앱이 저장한 Link가 `validate`를 통과하는지 확인). 앱에서 만든 형태라 초안이 없다 | FIPS 180-4 SHA-256 예제("abc") |
| `did-auth-keygen` | DID Auth 데모용 P-256 키쌍 두 개(서버, 클라이언트) 생성. 실행마다 값이 다르므로 비교하지 않는다. | 시험 벡터 없음(무작위) |
| `did-auth-client` | DID Auth 클라이언트: ECDH(raw_x) → SHA-256 → AES-128-CBC → MAC 8바이트. 학습용 예제, 공개 데모 키 | 독립 구현 대조(Node `crypto`, `reference/did-auth/did-auth.mjs`), 공개 시험 벡터 없음 |
| `did-auth-server` | DID Auth 서버: 같은 계산 체인으로 MAC을 다시 만들어 비교(`Verified`). 학습용 예제, 공개 데모 키 | `did-auth-client`와 같음 |
| `did-auth-demo` | 통합 예제: 클라이언트·서버 워크플로우를 사용자 정의 노드로 내장하고 키쌍과 nonce를 매 실행 새로 만들어 `Verified`가 `true`인지 확인. 앱에서 직접 만든 파일(초안 없음) | `did-auth-client`와 같음. 키와 nonce가 무작위라 판정값만 비교 |
| `mlkem-768-decaps` | ML-KEM-768 역캡슐화(전체 크기 2400바이트 복호화 키) → 공유 비밀 | C2SP CCTV `ML-KEM/intermediate/ML-KEM-768.txt`(`dk`, `c`, `K`) |
| `mlkem-roundtrip` | ML-KEM-768 키 생성 → 캡슐화 → 역캡슐화, 공유 비밀 일치 `bool` | 무작위라 판정만 대조 |
| `cmac-subkey`, `variables-aes-ecb` | 아래 설명 | RFC 4493 §4, FIPS 197 C.1 |

회귀 테스트는 `products/cli/tests/examples.test.ts`(CLI 실행·초안 펼침 일치)이다. 웹 앱에서 열기 시험은 내부 저장소에서 따로 수행한다.

### 노드 도움말용 예제 (`workflows/try/`)

노드 도움말의 "Try this node" 단추가 앱에서 여는 예제이다. 노드 하나에 예제 1~4개를 둔다.

```
workflows/try/
├── try.json                       # 노드 타입 ID → 예제 목록(slug, 영어·한국어 title/description). 첫 항목이 주 예제
└── <노드 타입 ID>/              # slug는 모든 예제에서 고유하다(탭 이름이 파일 이름이라서). 첫 예제는 노드 타입 ID, 이후는 <노드 타입 ID>-<이름>
    ├── <slug>.ncw                 # 최종 원본(앱에서 배치를 확정해 저장한 파일)
    ├── <slug>.expect.json         # 기대 출력(위 "검증된 예제"와 같은 형식)
    └── drafts/<slug>.json         # 초안. 앱에서 확정해 .ncw를 교체하면 지운다
```

작성 기준:

1. 보여 줄 값은 모두 `Workflow Output` 노드에 연결한다. 출력 포트를 눌러야만 값이 보이게 두지 않는다. `Workflow Output`은 워크플로우에 하나만 둘 수 있으므로 노드 하나에 포트를 여럿 둔다. 값을 보여 주는 것이 노드의 일인 `Output Inspector` 예제만 예외이다.
2. 입력은 `Static Value` 등으로 미리 올바른 값을 채운다. 사용자에게 값을 묻는 `Workflow Input`은 쓰지 않는다(대상 노드가 `Workflow Input`일 때만 예외). 올바른 값을 만들기 어려운 입력(예: RSA 공개키)은 키 생성 노드에서 무작위로 만들어 잇는다.
3. 노드는 왼쪽 입력에서 오른쪽 출력으로 열을 맞춰 배치하고 연결선이 꼬이지 않게 한다. 열 사이의 가로 간격은 모두 같게(노드 가장자리 사이 96) 두고, 같은 열의 노드는 격자 2칸(32) 간격으로 쌓아 세로 가운데를 맞춘다. 노드 이름은 역할이 드러나게 붙인다.
4. 키와 값은 공개 시험 벡터이거나 이 용도로만 만든 폐기용 값이다. `expect.json`의 `source`에 출처를 적는다.
5. 값이 실행마다 달라지는 예제(무작위 키 생성 등)는 값 대신 판정(`bool`, 길이)을 `Workflow Output`으로 함께 내보내고, `expect.json`은 그 판정만 비교한다.
6. 불필요한 변환 노드를 넣지 않는다. 출력은 `Bytes to Hex`·`Bytes to String` 같은 표기 변환 없이 노드의 출력을 그대로 `Workflow Output`에 잇고, 입력도 `Static Value`의 타입을 대상 노드가 받는 타입으로 직접 골라 `String to Bytes` 같은 변환 노드를 두지 않는다. 변환 노드가 예제의 대상일 때와 흐름에 꼭 필요한 연산(비교, 복호화 왕복)만 예외이다. 같은 입력을 알고리즘이 다른 노드 여러 개에 넣어 결과를 견주는 예제(해시, CRC)는 결과마다 `Workflow Output`의 포트를 하나씩 둔다.
7. 앱에서 배치를 고쳐 저장한 `.ncw`가 원본이다. 초안과 `.ncw`의 일치는 시험하지 않고, `.ncw`를 실행한 결과가 `expect.json`과 맞는지를 시험한다.

### 설명

- `workflows/cmac-subkey.ncw`: RFC 4493 CMAC 서브키. `Static Value`(키 `2b7e151628aed2a6abf7158809cf4f3c`, 영 블록) → `AES Encrypt`(ECB, 패딩 없음) → 스크립트 노드(`builtin-script.md` §12.1)로 `L`에서 `K1`, `K2`를 만든다. 실행하면 `k1 = fbeed618357133667c85e08f7236a8de`, `k2 = f7ddac306ae266ccf90bc11ee46d513b`이다.
- `workflows/variables-aes-ecb.ncw`: 변수 레지스트리를 쓰는 예제(변수 동봉 파일, `formatVersion` 2). FIPS-197 부록 C.1의 AES-128 벡터로, `Static Value`의 값이 변수 `$example.aes.key`(`000102…0f`)와 `$example.aes.plaintext`(`00112233…ff`)를 참조하고 `AES Encrypt`(ECB, 패딩 없음)로 암호화한다. 열면 두 변수의 등록 여부를 묻고, 실행하면 `69c4e0d86a7b0430d8cdb78070b4c55a`이다. 값으로 풀어 저장해도 같은 결과이다.
