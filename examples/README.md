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

- `drafts/<이름>.json`: 초안 원본. 인공지능이 따라 쓸 예시이다.
- `<이름>.ncw`: 초안을 `nodecrypto expand`로 펼친 패키지. 테스트가 초안을 펼친 결과와 같은지 확인한다.
- `<이름>.expect.json`: `{ "source", "inputs", "outputs" }`. `source`는 시험 벡터 출처(절 번호까지), `inputs`와 `outputs`는 CLI 값 표기이다(`cli-spec.md` §5).

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
| `did-auth-keygen` | DID Auth 데모용 P-256 키쌍 두 개(서버, 클라이언트) 생성. 실행마다 값이 다르므로 비교하지 않는다. | 시험 벡터 없음(무작위) |
| `did-auth-client` | DID Auth 클라이언트: ECDH(raw_x) → SHA-256 → AES-128-CBC → MAC 8바이트. 학습용 예제, 공개 데모 키 | 독립 구현 대조(Node `crypto`, `reference/did-auth/did-auth.mjs`), 공개 시험 벡터 없음 |
| `did-auth-server` | DID Auth 서버: 같은 계산 체인으로 MAC을 다시 만들어 비교(`Verified`). 학습용 예제, 공개 데모 키 | `did-auth-client`와 같음 |
| `did-auth-demo` | 통합 예제: 클라이언트·서버 워크플로우를 사용자 정의 노드로 내장하고 키쌍과 nonce를 매 실행 새로 만들어 `Verified`가 `true`인지 확인. 앱에서 직접 만든 파일(초안 없음) | `did-auth-client`와 같음. 키와 nonce가 무작위라 판정값만 비교 |
| `mlkem-768-decaps` | ML-KEM-768 역캡슐화(전체 크기 2400바이트 복호화 키) → 공유 비밀 | C2SP CCTV `ML-KEM/intermediate/ML-KEM-768.txt`(`dk`, `c`, `K`) |
| `mlkem-roundtrip` | ML-KEM-768 키 생성 → 캡슐화 → 역캡슐화, 공유 비밀 일치 `bool` | 무작위라 판정만 대조 |
| `cmac-subkey`, `variables-aes-ecb` | 아래 설명 | RFC 4493 §4, FIPS 197 C.1 |

회귀 테스트는 `products/cli/tests/examples.test.ts`(CLI 실행·초안 펼침 일치)이다. 웹 앱에서 열기 시험은 내부 저장소에서 따로 수행한다.

### 설명

- `workflows/cmac-subkey.ncw`: RFC 4493 CMAC 서브키. `Static Value`(키 `2b7e151628aed2a6abf7158809cf4f3c`, 영 블록) → `AES Encrypt`(ECB, 패딩 없음) → 스크립트 노드(`builtin-script.md` §12.1)로 `L`에서 `K1`, `K2`를 만든다. 실행하면 `k1 = fbeed618357133667c85e08f7236a8de`, `k2 = f7ddac306ae266ccf90bc11ee46d513b`이다.
- `workflows/variables-aes-ecb.ncw`: 변수 레지스트리를 쓰는 예제(변수 동봉 파일, `formatVersion` 2). FIPS-197 부록 C.1의 AES-128 벡터로, `Static Value`의 값이 변수 `$example.aes.key`(`000102…0f`)와 `$example.aes.plaintext`(`00112233…ff`)를 참조하고 `AES Encrypt`(ECB, 패딩 없음)로 암호화한다. 열면 두 변수의 등록 여부를 묻고, 실행하면 `69c4e0d86a7b0430d8cdb78070b4c55a`이다. 값으로 풀어 저장해도 같은 결과이다.
