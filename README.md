# IOC Extractor (Offline)

Basit bir metin içinden **IPv4** ve **alan adlarını (domain)** çıkarır.  
Tamamen **offline** çalışır; WHOIS/DNS sorgusu yapmaz.  
Girişte defanged/obfuscated kalıpları (ör. `hxxp`, `[.]`, `(.)`) kısmen **refang** eder.

## ✨ Özellikler
- IPv4 & domain regex çıkarımı
- `hxxp` → `http`, `[.]` / `(.)` / `{.}` → `.` dönüşümü
- Yinelenen IOC’ları otomatik temizler
- Çıktı iki başlık: IPv4 ve Domains

## 🚀 Kullanım
```bash
python ioc_extractor.py samples.txt
python ioc_extractor.py notes1.txt notes2.txt -o out.txt
cat logs.txt | python ioc_extractor.py --stdin
```

## Örnek çıktı (iocs.txt)
# IOCs — IPv4
8.8.8.8
1.1.1.1

# IOCs — Domains
example.com
login.example.com
