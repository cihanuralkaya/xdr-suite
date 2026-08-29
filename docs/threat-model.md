# Tehdit Modeli ve İnceleme Kararları

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
