#!/usr/bin/env python3
"""
IOC Extractor (Offline)

Basit bir metin içinden IPv4 ve alan adlarını (domain) çıkarır.
- Girdi: 1+ dosya ya da --stdin
- Çıktı: iocs.txt (IP'ler ve domain'ler ayrı başlıklarda)
- Hiçbir dış bağımlılık yoktur.

Özellikler
- Defanged/obfuscated metinleri kısmen geri çevirir ("refang"): hxxp -> http, [.] -> . , (.) -> .
- Yinelenenleri temizler (set)
- IPv4 ve domain için makul regex'ler

Kullanım
  python ioc_extractor.py samples.txt
  python ioc_extractor.py --stdin < logs.txt
  python ioc_extractor.py notes1.txt notes2.txt -o out_iocs.txt
"""
from __future__ import annotations
import argparse
import sys
import re
from typing import Iterable, Set, Tuple

REFANG_MAP = {
    'hxxp://': 'http://',
    'hxxps://': 'https://',
    'hxxp': 'http',
    '[.]': '.',
    '(.)': '.',
    '{.}': '.',
}

# IPv4 (0-255) — pratik amaçlı yeterli
OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
IPV4_RE = re.compile(rf"\b{OCTET}\.{OCTET}\.{OCTET}\.{OCTET}\b")

# Domain — harf/rakam ve tire içeren etiketler + harf TLD (2-63)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b",
    re.IGNORECASE
)

def refang(text: str) -> str:
    out = text
    for k, v in REFANG_MAP.items():
        out = out.replace(k, v)
    # Bazı yazarlar '[dot]' veya '{dot}' kullanır
    out = re.sub(r"\[(?:dot|DOT)\]", ".", out)
    out = re.sub(r"\{(?:dot|DOT)\}", ".", out)
    return out

def extract(text: str) -> Tuple[Set[str], Set[str]]:
    text = refang(text)
    ips = set(m.group(0) for m in IPV4_RE.finditer(text))
    domains = set(m.group(0).lower() for m in DOMAIN_RE.finditer(text))
    # IP'leri domain listesinden dışla (ihtimal düşük de olsa)
    domains = {d for d in domains if not IPV4_RE.fullmatch(d)}
    return ips, domains

def read_sources(files: Iterable[str], use_stdin: bool) -> str:
    chunks = []
    if use_stdin:
        chunks.append(sys.stdin.read())
    for path in files:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            chunks.append(f.read())
    return "\n".join(chunks)

def write_output(path: str, ips: Set[str], domains: Set[str]) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write("# IOCs — IPv4\n")
        for ip in sorted(ips):
            f.write(ip + "\n")
        f.write("\n# IOCs — Domains\n")
        for d in sorted(domains):
            f.write(d + "\n")

def main():
    ap = argparse.ArgumentParser(description='Basit IOC (IPv4 & Domain) çıkarıcı')
    ap.add_argument('inputs', nargs='*', help='Girdi dosyaları')
    ap.add_argument('--stdin', action='store_true', help='Veriyi stdin üzerinden al')
    ap.add_argument('-o', '--output', default='iocs.txt', help='Çıktı dosya yolu (varsayılan: iocs.txt)')
    args = ap.parse_args()

    if not args.inputs and not args.stdin:
        ap.error('En az bir dosya belirtin veya --stdin kullanın.')

    text = read_sources(args.inputs, args.stdin)
    ips, domains = extract(text)

    write_output(args.output, ips, domains)

    print(f"Bulunan IP sayısı   : {len(ips)}")
    print(f"Bulunan domain sayısı: {len(domains)}")
    print(f"Yazıldı: {args.output}")

if __name__ == '__main__':
    main()
