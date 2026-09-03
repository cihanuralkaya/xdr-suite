# Tehdit Modeli ve İnceleme Kararları
# Threat Model & Review Decisions

**Türkçe** · [English](#english)

İlk mimari incelemesinde tespit edilen bulgular ve iskelette karşılığında
alınan kararlar.

| # | Bulgu | Karar / Karşılık | Nerede |
|---|-------|------------------|--------|
| 1 | Şema kırık (`policies` yok) + şifreli log sorgulanamaz | `policies` eklendi, FK düzeltildi; `event_logs` partitioned + JSONB, at-rest şifreleme | `db/schema.sql` |
| 2 | Düz SHA-256 blind index kırılabilir (MAC ~48 bit) | HMAC(keyed) blind index (`*_bidx BYTEA`) | `db/schema.sql` |
| 3 | Yerel saatle politika bypass edilir | Heartbeat yanıtı `server_time` taşır; politika buna çıpalı | `proto/.../agent.proto` |
| 4 | OTA sadece hash → MITM | Manifesto `signature` alanı; ajan imzayı doğrular | `agent.proto`, `ota_releases` |
| 5 | Dual-process tamper yetersiz | Watchdog "ilk savunma" olarak işaretlendi; gerçek koruma Faz 7 (sürücü/PPL) | `agent/cmd/watchdog` |
| 6 | Enrollment/PKI tanımsız | `EnrollmentService` + `enrollment_tokens` + `agent_certificates` | `enrollment.proto`, `db` |
| 7 | "Sandbox" gerçek sınır değil | Karar: script yürütme ayrı süreç + kısıtlı token/AppContainer (Faz 2+) | — |
| 8 | Otomatik karantina + ML FP riski | Kademeli yanıt (uyar→kısıtla→izole), kritikte human-in-loop | Faz 5/6 |
| 9 | Offline senaryolar | Store-and-forward olay tamponu (`sequence`/`EventAck`); offline uninstall açık | `agent.proto` |
| 10 | Ölçek/operasyon | RBAC (`admins`) + değişmez denetim izi (`audit_log`) | `db/schema.sql` |
| 11 | KVKK | Bkz. `docs/kvkk.md`; saklama = partition DROP | `db`, `kvkk.md` |

## Güven sınırları

- **Ajan gövdesi güvenilmez:** Sunucu, kimliği daima mTLS istemci
  sertifikasından çıkarır; `AgentIdentity.device_id` yalnız bilgilendirmedir.
- **Ana anahtar RAM'de:** DB at-rest şifreli; anahtar serviste tutulur, diske
  düz yazılmaz. Sunucuya kök erişim = anahtar riski (kabul edilen sınır).
- **Enrollment token tek kullanımlık ve süreli:** Sızarsa etkisi tek cihaz ve
  kısa pencere ile sınırlı.

## Açık konular (henüz karar bekleyen)

- Offline meşru kaldırma için imzalı offline token mekanizması.
- Sertifika iptali dağıtımı: CRL mi kısa-ömür+yenileme mi.
- İstemci installer'ında token gömülü mü, elle mi girilecek (bkz. architecture).

---

# English

Findings identified in the initial architecture review and the decisions taken in
response in the skeleton.

| # | Finding | Decision / Response | Where |
|---|---------|---------------------|-------|
| 1 | Schema broken (no `policies`) + encrypted log not queryable | `policies` added, FK fixed; `event_logs` partitioned + JSONB, at-rest encryption | `db/schema.sql` |
| 2 | Plain SHA-256 blind index is breakable (MAC ~48 bit) | HMAC(keyed) blind index (`*_bidx BYTEA`) | `db/schema.sql` |
| 3 | Policy bypassable via local clock | Heartbeat response carries `server_time`; policy is anchored to it | `proto/.../agent.proto` |
| 4 | OTA hash-only -> MITM | Manifest `signature` field; the agent verifies the signature | `agent.proto`, `ota_releases` |
| 5 | Dual-process tamper protection insufficient | Watchdog marked as a "first line of defense"; real protection is Phase 7 (driver/PPL) | `agent/cmd/watchdog` |
| 6 | Enrollment/PKI undefined | `EnrollmentService` + `enrollment_tokens` + `agent_certificates` | `enrollment.proto`, `db` |
| 7 | "Sandbox" is not a real boundary | Decision: script execution in a separate process + constrained token/AppContainer (Phase 2+) | - |
| 8 | Auto-quarantine + ML false-positive risk | Graded response (warn -> restrict -> isolate), human-in-loop on critical | Phase 5/6 |
| 9 | Offline scenarios | Store-and-forward event buffer (`sequence`/`EventAck`); offline uninstall is an open item | `agent.proto` |
| 10 | Scale/operations | RBAC (`admins`) + immutable audit log (`audit_log`) | `db/schema.sql` |
| 11 | Data protection (KVKK) | See `docs/kvkk.md`; retention = partition DROP | `db`, `kvkk.md` |

## Trust boundaries

- **Agent body untrusted:** The server always derives identity from the mTLS client
  certificate; `AgentIdentity.device_id` is informational only.
- **Master key in RAM:** the DB is at-rest encrypted; the key is held in the service,
  never written to disk in plaintext. Root access to the server = key risk (an
  accepted boundary).
- **Enrollment token single-use and time-limited:** if leaked, the impact is limited
  to one device and a short window.

## Open items (still pending a decision)

- A signed offline token mechanism for legitimate offline removal.
- Certificate-revocation distribution: CRL vs. short-lifetime + renewal.
- Token embedded in the client installer vs. entered manually (see architecture).
