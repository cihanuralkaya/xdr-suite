# Veritabanı

`schema.sql` — düzeltilmiş PostgreSQL şeması (PostgreSQL 14+).

## Kurulum

```bash
createdb xdr
psql -U postgres -d xdr -f schema.sql
```

## Notlar

- **Blind index (HMAC):** `*_bidx` sütunları uygulama katmanında
  `HMAC-SHA256(sunucu_gizli_anahtarı, normalize_değer)` ile üretilir. Düz hash
  kullanmayın (MAC adres uzayı brute-force'a açıktır).
- **At-rest şifreleme:** `event_logs` sorgulanabilir kalması için alan-bazlı
  şifrelenmez; gizliliği şifreli tablespace / disk (TDE) düzeyinde sağlanır.
  Serbest-metin kimlik alanları (`*_encrypted`) `pgcrypto` ile şifrelidir.
- **Partition yönetimi:** `event_logs` RANGE partition'lıdır. Üretimde
  `pg_partman` veya bir cron görevi ile gelecek partition'lar önceden
  oluşturulmalı ve saklama süresi dolanlar DROP edilmelidir (bkz. `docs/kvkk.md`).
- **Migration'lar:** İleride `migrations/` altına sıralı `.sql` dosyaları
  (ör. golang-migrate) eklenecek; `schema.sql` başlangıç anlık görüntüsüdür.
