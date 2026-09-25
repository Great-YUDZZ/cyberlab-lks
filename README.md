# CyberLab LKS - Cybersecurity Toolkit & CTF Analysis Workspace

Workstation taktis dan toolkit analisis keamanan siber mandiri (*all-in-one*) untuk persiapan **LKS Cyber Security** dan **CTF (Capture The Flag)**. Berjalan sepenuhnya di sisi klien (*client-side isolated*), cepat, aman, dan tanpa telemetri eksternal.

## 🛡️ 8 Kategori Modul Utama

1. **Cryptography**:
   - Classical ciphers: Caesar (ROT-N), ROT13, ROT47, Atbash, Vigenère, Affine Cipher, Morse Code.
   - Brute-force helper (shift 0-25).
   - Multi-Radix & Encoders: Base64, Hexadecimal, Binary (8-bit ASCII), URL Encoding, HTML Entities.
   - Heuristic Auto-Decoder untuk mendeteksi pola encoding.
   - Single-byte XOR engine & brute-force helper (keys 0-255).
   - Modular Arithmetic: GCD, Extended Euclidean Algorithm ($ax + by = \gcd(a,b)$), Modular Inverse, ModPow ($b^e \pmod m$).
   - Educational RSA parameter solver: hitung $n, \phi(n), d$ dari $p, q, e$.
   - Multi-hash digest: SHA-256, SHA-1, SHA-512.

2. **Digital Forensics**:
   - Magic bytes file signature detector (PNG, JPG, GIF, ZIP, RAR, PDF, ELF, PE, SQLite, PCAP).
   - Shannon Entropy calculator ($0.0 - 8.0$) untuk deteksi kompresi/enkripsi.
   - Interactive Hexdump & ASCII viewer dengan offset addressing.
   - Printable Strings extractor (ASCII & Unicode).

3. **Steganography**:
   - LSB Bit-plane visualizer untuk kanal Red, Green, Blue, Alpha (Bit 0-7).
   - Canvas pixel inspector & preview ekstraksi string biner tersembunyi.
   - Deteksi file carving & PNG/JPEG marker.

4. **Web Exploitation (CTF Labs)**:
   - JSON Web Token (JWT) structure decoder (Header, Claims/Payload, Signature).
   - HTTP Security Headers compliance auditor (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
   - Educational safe matrices untuk kerentanan web (SQLi, XSS, SSRF, IDOR, Path Traversal).

5. **Reverse Engineering**:
   - Static header inspection untuk binary ELF Linux dan Windows PE.
   - Section visualizer (`.text`, `.data`, `.rodata`).
   - Searchable assembly opcode reference (x86, x64, ARM).

6. **Pwn & Binary Exploitation**:
   - Binary security mitigation checker (NX, Stack Canary, PIE, RELRO).
   - Cyclic pattern generator (De Bruijn) & offset finder.
   - Endianness & integer converter (Big Endian, Little Endian, raw bytes).

7. **OSINT Reconnaissance**:
   - IPv4 / IPv6 CIDR subnetting calculator.
   - Passive reconnaissance helpers (URL & domain parsing, email heuristics).
   - Google Dork search query generator (Index Of, config/env files, login portals).

8. **Miscellaneous**:
   - Multi-radix converter (Decimal, Hexadecimal, Binary, Octal).
   - Bitwise operations calculator (AND, OR, XOR, SHL, SHR).
   - Tool Chaining Pipeline (Base64 -> Hex -> XOR -> Reverse).
   - Global Auto-Triage modal untuk analisis berkas & string kilat.
   - CTF Challenge Workspace dengan penyimpanan lokal autosave.

## 🚀 Cara Menjalankan

Aplikasi web ini bersifat static dan mandiri (zero external server dependencies). Anda dapat menjalankannya langsung:

```bash
# Menggunakan Node.js http server:
npx serve .

# Atau menggunakan Python:
python3 -m http.server 3003
```

Akses melalui browser di `http://localhost:3003`.

## 📜 Lisensi
MIT License - Dibuat untuk pelatihan & persiapan LKS Cyber Security.
