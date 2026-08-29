# KVKK / Gizlilik Notları

Bu sistem ağ trafiği ve süreç verisi işler; kurumsal bağlamda meşru olsa da
KVKK (ve muadili GDPR) gereklilikleri tasarıma baştan girer.

## İlkeler

- **Şeffaflık / bilgilendirme:** Çalışanlara izleme kapsamı açıkça bildirilir;
  gizli/örtük izleme yapılmaz.
- **Veri minimizasyonu:** Yalnız güvenlik amacı için gerekli veri toplanır.
  İçerik (ör. dosya/klavye içeriği) değil, meta-veri (süreç adı, bağlantı
  meta-verisi) hedeflenir.
- **Amaçla sınırlılık:** Toplanan veri güvenlik/politika uygulaması dışında
  kullanılmaz.
- **Saklama süresi:** `event_logs` zaman-bazlı partition'lıdır; saklama süresi
  dolan partition'lar DROP edilir (varsayılan öneri: 90 gün — kurumun
  politikasına göre ayarlanır).
- **Erişim kontrolü + denetim:** Yönetici erişimi RBAC ile sınırlı; hassas
  aksiyonlar (kaldırma OTP'si, karantina) `audit_log`'a değişmez yazılır.
- **Şifreleme:** Hassas alanlar at-rest şifreli; iletişim mTLS ile şifreli.

## Yapılacaklar

- [ ] Çalışan bilgilendirme metni / aydınlatma metni şablonu.
- [x] Saklama süresini otomatik uygulayan partition DROP görevi —
      `server/internal/retention` (C2'de günlük çalışır; `XDR_RETENTION_DAYS`,
      varsayılan 90 gün). Dolan `event_logs` aylık partition'ları düşürülür,
      gelecek aylar önceden oluşturulur.
- [ ] Veri sahibi başvuru (erişim/silme) süreçlerinin operasyonel karşılığı.
