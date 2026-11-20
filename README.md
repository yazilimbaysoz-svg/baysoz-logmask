# baysoz-logmask

Log satırlarındaki kişisel verileri ve sırları **doğrulayarak** tespit edip maskeleyen, bağımlılıksız bir Python CLI ve kütüphane.

## Sorun

Uygulama logları gerçek hayatta e-posta, telefon, TCKN, IBAN, kart numarası, IP adresi, JWT veya `api_key=...` gibi değerlerle doludur. Bu loglar bir hata bildirimine, bilet sistemine ya da paylaşılan bir dosyaya kopyalandığında kişisel veri sızıntısı oluşur. Eleştiri gerektiren nokta şu: kaba bir sayı desenle her 11 haneli değeri kimlik numarası sanmak, logdaki zaman damgalarını ve para tutarlarını bozar. `baysoz-logmask` yalnızca sağlama (checksum) testini geçen adayları maskeler; böylece yanlış pozitifler azalır.

## Kurulum

Python 3.12 ve [uv](https://docs.astral.sh/uv/) gereklidir. Harici servis, veritabanı veya yerel LLM yoktur; çalışma zamanı bağımlılığı sıfırdır.

```bash
uv venv
uv pip install -e .
uv run baysoz-logmask --version
```

## Örnek

```bash
printf 'kullanici=aday@example.com kimlik=10000000146 ip=192.168.1.44\n' \
  | uv run baysoz-logmask
# kullanici=[EMAIL] kimlik=[TCKN] ip=[IP]

uv run baysoz-logmask uygulama.log > temiz.log
uv run baysoz-logmask --stats uygulama.log
uv run baysoz-logmask --json uygulama.log
uv run baysoz-logmask --list-rules
```

Dosya verilmezse girdi stdin'den okunur. `--stats` kural başına düşen sayıları stderr'e JSON olarak verir; `--json` tüm girdileri dosya adı → maskelenmiş metin eşlemesi olarak döndürür.

### Kararlı takma ad (hash) modu

```bash
export LOGMASK_KEY="$(uv run python -c 'import secrets; print(secrets.token_hex(32))')"
printf 'kimlik=10000000146\n' | uv run baysoz-logmask --mode hash
# kimlik=[TCKN:1f0c...]
```

Aynı anahtarla aynı değer her zaman aynı özeti üretir; farklı kural türleri ayrı ad alanı kullanır. Anahtar bir sır yöneticisinden gelmelidir; kodda veya depoda saklanmamalıdır. Anahtar yoksa komut `hata: LOGMASK_KEY ortam değişkeni boş` mesajıyla çıkış kodu 2 döner.

## Desteklenen kurallar

| Kural | Ne maskeleyer | Doğrulama |
| --- | --- | --- |
| `private_key` | PEM özel anahtar blokları | Benzersiz BEGIN/END işaretleri |
| `jwt`, `bearer` | JWT ve Bearer belirteçleri | Önek ve biçim |
| `aws_key`, `github_token` | AWS/GitHub erişim anahtarları | Bilinen önek + uzunluk |
| `secret_assignment` | `api_key=`, `token:`, `password:` vb. atamalar | Anahtar sözcük eşleşmesi |
| `iban` | IBAN | ISO 13616 mod-97 |
| `card` | Ödeme kartı numaraları | Luhn |
| `tckn` | Türkiye kimlik numaraları | İki sağlama hanesi |
| `email`, `phone_tr`, `ipv4` | E-posta, cep telefonu, IPv4 | Biçim ve aralık denetimi |

Kurallar öncelik sırasına göre uygulanır; çakışan eşleşmelerde daha erken başlayan, aynı yerde başlayanlarda daha yüksek öncelikli kural kazanır. Çok satırlı özel anahtar blokları dışında işleme satır satırdır; satır sonları korunur.

## Mimari

```
CLI (argparse) ──► Masker ──► RULES ──► validators
                     │          │          └─ checksum / biçim denetimi
                     │          └─ desen + öncelik + etiket
                     └─ çakışma çözümü ─► etiket veya HMAC-SHA256 özeti
```

- `src/baysoz_logmask/validators.py`: saf doğrulama işlevleri (TCKN, IBAN, Luhn, e-posta, IP, telefon).
- `src/baysoz_logmask/rules.py`: sıralı kural tanımları ve değiştirge etiketleri.
- `src/baysoz_logmask/masker.py`: eşleşme toplama, çakışma çözümü, iki mod, akış işleme ve istatistikler.
- `src/baysoz_logmask/cli.py`: dosya/stdin girdisi, JSON/istatistik çıktıları, hata kodları.
- `src/baysoz_logmask/__main__.py`: `python -m baysoz_logmask` giriş noktası.

Kütüphane olarak kullanım:

```python
from baysoz_logmask import Masker

masker = Masker()
temiz, sayimlar = masker.mask_with_stats("posta=aday@example.com")
print(temiz, sayimlar)
```

Maskeleme idempotenttir: çıktı tekrar maskelense bile değişmez. Ağ erişimi, dosya sistemi yazımı (CLI çıktısı hariç) veya model çağrısı yapılmaz.

## Geliştirme ve kalite

```bash
uv venv
uv pip install -e .
uv pip install pytest
uv run pytest -q
ruff check .
semgrep scan --config p/default .
```

## Sınırlar

Bu araç bilinen desenleri yakalar; uzman bir DLP çözümünün yerine geçmez. Maskelenmiş logları yine de paylaşmadan önce gözden geçirin. Yeni bir kural eklemek için `rules.py` içine bir `Rule` ekleyip `tests/` altına pozitif ve negatif örnek yazın.

## Lisans

MIT — bkz. [LICENSE](LICENSE). © 2026 BAYSOZ YAZILIM.
