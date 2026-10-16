# Publicly Verifiable Cloud Framework

### Public Verifiable Server-Aided Revocable Attribute-Based Encryption (PV-SR-ABE)

**Python · AWS Lambda · Docker · Charm-Crypto · PBC · AES-256-GCM · Amazon S3**

> **Research proof of concept — not a production-ready security service.** This repository explores how a pairing-based, publicly verifiable, revocable attribute-based encryption scheme can be implemented in a serverless cloud workflow. Its engineering extensions and tests should not be confused with the formal security proofs in the research paper.

## The problem: can you trust outsourced decryption?

Imagine an organisation storing confidential documents in the cloud. Access should depend on a user's attributes (such as `Department: Engineering` and `Project: Alpha`), and access must be revocable when an employee leaves or their credentials are compromised.

**Attribute-Based Encryption (ABE)** enforces fine-grained access policies cryptographically. **Revocable ABE (RABE)** adds a way to prevent revoked users from obtaining valid transformation keys for new time periods. Because pairing-based operations can be expensive for clients, a cloud server can perform most of the decryption-related computation on their behalf.

But the cloud server may be untrusted. How can a user—or an independent auditor—know that its outsourced computation is correct **before** attempting decryption?

This project investigates that question through **Public Verifiable Server-Aided Revocable ABE (PV-SR-ABE)**.

## The idea: verify first, decrypt second

In many verifiable outsourced-decryption approaches, only a legitimate user can check a result, often after decryption. PV-SR-ABE separates **public verification** from **private message recovery**:

```text
Conventional private verification:
  Untrusted server → Outsourced result → User decrypts → User checks

PV-SR-ABE:
  Untrusted server → Transformed result (π) → Anyone verifies → Authorised user decrypts
```

A public verifier uses public parameters, the ciphertext, and a **user-specific public verification key** (`vk_ID`) to check the transformation. The verifier does **not** need the user's private decryption key or the plaintext. Only an authorised, non-revoked user satisfying the access policy can complete decryption.

The underlying research construction also uses a user-specific random value in the transformation, rather than a single static verification result shared by every user.

## Example: confidential document sharing

Consider an illustrative company sharing a sensitive engineering report:

1. A **Private Key Generator (PKG)** establishes the system and issues attribute-linked user credentials.
2. A **data owner** encrypts the report under a policy such as `Engineering AND Project-Alpha`, with a designated time period.
3. The encrypted data is stored in the cloud. A cloud service derives a transformation key using the relevant time-update material and computes an outsourced result for an eligible user.
4. **Any independent auditor** can verify the published transformed result without knowing the user's private key.
5. The **authorised user** verifies the result and performs the final local decryption.
6. If the user is **revoked**, the key-update mechanism prevents them from deriving a valid transformation key for the applicable subsequent periods.

*This is an application scenario illustrating the scheme, not a claim of a deployed enterprise product.*

## System architecture

![PV-SR-ABE system architecture](architecture/system_architecture.png)

The prototype separates local authority operations, cloud processing, and public auditing:

| Component | Responsibility |
|---|---|
| **PKG (local / trusted)** | `Setup`, `UserKG`, `TKeyUp`, `Revoke`; manages master secrets and user credentials |
| **Data owner** | Encrypts data under an attribute policy and time period |
| **AWS Lambda (cloud / untrusted computation)** | Processes encryption and transformation requests in a container with native pairing libraries |
| **Amazon S3 / local simulation** | Stores encrypted bundles, configuration, published verification records, and audit data |
| **Public verifier** | Checks outsourced results using publicly available information |
| **Data user** | Holds a private decryption key and recovers plaintext locally after verification |

The `crypto/lambda_service.py` implementation handles S3-style `inbox/` encryption events and `requests/` transformation events. It can publish transformed results and append outcomes to a hash-chained audit log. The standalone `crypto/public_verify.py` supports individual-record verification and log-monitoring workflows. These are **prototype features**, not an independent guarantee that every cloud configuration is tamper-proof.

## What is implemented?

The research paper defines **nine algorithms**:

| Algorithm | Purpose |
|---|---|
| `Setup` | Generate public parameters and master secret material |
| `UserKG` | Issue user decryption, verification, and long-term transformation keys |
| `TKeyUp` | Produce time-period update material for non-revoked users |
| `TranKG` | Derive a user's short-term transformation key, or fail |
| `Encrypt` | Encrypt under an access policy and time period |
| `Transform` | Outsource policy-dependent pairing computation |
| `Verify` | Publicly validate the transformed result |
| `Decrypt` | Recover the protected message with the user's private key |
| `Revoke` | Update the revocation state |

The repository includes a pairing-based implementation of these operations in `crypto/pv_core.py`, command-line utilities, AWS Lambda integration, and test scripts. **Theoretical correctness/security claims belong to the paper; code-level assurance depends on tests, configuration, and further review.**

### Hybrid encryption for real files

The paper's ABE construction operates on pairing-group elements. To handle arbitrary file contents, the prototype uses a hybrid design:

```text
Data owner:
  Random GT session element ──> key derivation ──> AES-256-GCM key
           │                                         │
           └── PV-SR-ABE encryption                  └── Encrypt file bytes
                      │                                         │
                      └──────────── Stored ciphertext bundle ──┘

Data user:
  Verify transformed ABE result → Recover session element
       → Derive AES key → AES-256-GCM decrypt → Plaintext
```

This is an **engineering adaptation** of the paper's group-element message construction. Its security as a combined hybrid system should be analysed separately rather than assumed solely from the paper's IND-sCPA result.

## Technology stack

| Technology | Role |
|---|---|
| **Python** | Cryptographic workflow, CLIs, verification and tests |
| **Charm-Crypto + PBC + GMP** | Bilinear pairing operations and big-integer arithmetic |
| **AES-256-GCM** | Authenticated encryption of file contents |
| **Docker** | Packages native dependencies for a Linux runtime |
| **AWS Lambda** | Event-driven cloud processing via a container image |
| **Amazon S3** | Cloud object storage and request/record exchange |
| **Ed25519** | Signing selected public directory/parameter information in the publication workflow |
| **pytest** | Test scenarios for encryption, policy failure and time mismatch |

## Repository guide

```text
.
├── architecture/
│   └── system_architecture.png
├── crypto/
│   ├── pv_core.py              # Core PV-SR-ABE algorithms
│   ├── ta_local.py             # PKG setup, user keys, updates, revocation
│   ├── lambda_encrypt.py       # Hybrid encryption CLI
│   ├── client_decrypt.py       # Local verification/decryption path
│   ├── lambda_service.py       # S3-triggered cloud workflow
│   ├── public_verify.py        # Independent public verification
│   ├── client_request.py       # Request/response workflow
│   ├── export_public.py        # Public parameters and signed directory
│   ├── pv_publish.py           # Publication and audit helpers
│   └── pv_store.py             # Local and S3 storage adapters
├── docker/
│   └── Dockerfile
├── docs/
│   ├── algorithm_overview.md
│   ├── deployment.md
│   ├── security_model.md
│   └── PUBLIC_VERIFICATION.md
├── example/
├── tests/
├── paper/
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Getting started

**Prerequisites:** Docker, or a compatible Python environment with Charm-Crypto, PBC and GMP already installed. Pairing dependencies are native libraries; `pip install -r requirements.txt` alone may not provide a working environment on Windows.

The Dockerfile is under `docker/`, and the Lambda container configuration may require AWS-specific settings. Start with the detailed [deployment guide](docs/deployment.md) and [public-verification workflow](docs/PUBLIC_VERIFICATION.md).

For the original local CLI demonstration, the Python entry points live in `crypto/`. After installing the required dependencies, run commands from that directory:

```bash
cd crypto

# Initialise local authority state (contains secret material)
python ta_local.py setup --curve SS512 --depth 4 --out keys/pv_setup.json

# Issue a user credential
python ta_local.py userkg --setup keys/pv_setup.json \
  --id alice@example.com --attrs "A,C" --out keys/alice_user.json

# Encrypt a sample message
python lambda_encrypt.py --setup keys/pv_setup.json \
  --policy "(A and C)" --t 1 \
  --plaintext "confidential record" --store_dir keys/store

# Issue a time-update key
python ta_local.py tkeyup --setup keys/pv_setup.json \
  --t 1 --out keys/tuk_t1.json
```

The encryption command prints an object identifier. Use that value in the next step:

```bash
python client_decrypt.py --setup keys/pv_setup.json \
  --user keys/alice_user.json --tuk keys/tuk_t1.json \
  --object_id YOUR_OBJECT_ID --store_dir keys/store
```

These commands illustrate the intended CLI workflow; they have **not been re-executed as part of preparing this README**. Use test data only. Never commit generated `keys/` material.

## Testing and validation

The repository includes tests intended to cover:

| Test | Scenario | Intended outcome |
|---|---|---|
| `tests/test_e2e_ok.py` | Eligible user, matching policy and time | Successful verification and plaintext recovery |
| `tests/test_policy_fail.py` | Attributes do not satisfy the policy | Access/decryption rejected |
| `tests/test_time_fail.py` | Update period differs from ciphertext period | Transformation or verification fails |
| `crypto/tests/test_service_local.py` | Local cloud-service simulation | Exercises the service workflow |

The top-level test scripts refer to CLI files by path and may need adjustment for the current `crypto/` directory layout. **Do not interpret their presence as proof that the test suite passes unchanged on a fresh checkout.** Test outcomes and cloud benchmarks should be reported only after running them in a documented environment.

## Security model and limitations

The accompanying paper analyses **selective IND-CPA security in a one-user revocation setting** and **selective public verifiability** based on a Verifiable Delegable Computation model. Those are formal claims about the paper's specified construction and assumptions—not an audit of this AWS prototype.

Important deployment considerations:

- **Master secrets stay with the PKG.** Do not place `msk`, generated private keys, or signing secrets in S3 public objects, container images, or Git history.
- **Public verification is not public decryption.** Auditors can validate transformed results but cannot recover plaintext without an authorised user's decryption key.
- **Revocation is time-based.** Its effect depends on correct key-update distribution and enforcement of time-period matching; it does not automatically erase previously obtained plaintext.
- **The prototype uses research-oriented pairing parameters.** Do not assume modern production security levels or post-quantum resistance.
- **Cloud controls still matter.** IAM, bucket policies, secure transport, logging integrity, authentication, key rotation and error handling require independent hardening.
- **The hybrid KEM/DEM integration and operational protocol** need their own security analysis and review before production use.

## Research background

**Luqi Huang, Fuchun Guo, Willy Susilo, and Yumei Li.** *Public Verifiable Server-Aided Revocable Attribute-Based Encryption.* Research manuscript included in [`paper/`](paper/).

The paper introduces public verification of untrusted outsourced computation, a **verify-then-decrypt** approach, and user-specific transformed results within a revocable ABE design. It presents formal security models and proofs for the specified construction.

For technical details, see [Algorithm Overview](docs/algorithm_overview.md), [Security Model](docs/security_model.md), and the [research manuscript](paper/).

---

*From cryptographic research to a testable cloud-security prototype: exploring accountable outsourced computation without giving the cloud the user's private decryption key.*
