/**
 * CyberLab LKS - High-Performance Cybersecurity & CTF Engine
 * Client-Side Isolated, Zero-Telemetry, Modular Architecture
 */

// ============================================================================
// GLOBAL STATE & STORAGE
// ============================================================================
const state = {
  activeView: 'dashboard',
  activeCryptoTab: 'classical',
  activeForensicsTab: 'file-analyzer',
  activeStegoTab: 'image-analyzer',
  activeWebTab: 'jwt-analyzer',
  activeRevTab: 'binary-id',
  activePwnTab: 'cyclic-pattern',
  activeOsintTab: 'cidr-calc',
  activeMiscTab: 'radix-converter',
  favorites: JSON.parse(localStorage.getItem('cyberlab_favorites') || '[]'),
  recents: JSON.parse(localStorage.getItem('cyberlab_recents') || '[]'),
  notes: localStorage.getItem('cyberlab_notes') || '',
  pipelineSteps: []
};

// UI Feedback: Toast Notification System
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let tag = '[INFO]';
  if (type === 'success') tag = '[OK]';
  if (type === 'error') tag = '[ERR]';
  if (type === 'warning') tag = '[WARN]';
  
  toast.innerHTML = `<span class="toast-tag">${tag}</span><span class="toast-msg">${message}</span>`;
  container.appendChild(toast);
  
  requestAnimationFrame(() => {
    toast.classList.add('toast-show');
  });

  setTimeout(() => {
    toast.classList.remove('toast-show');
    setTimeout(() => toast.remove(), 250);
  }, 3000);
}

// Clipboard helper with visual status
function copyToClipboard(text, msg = 'Tersalin ke clipboard.') {
  if (!text) {
    showToast('Tidak ada data untuk disalin', 'warning');
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(msg, 'success');
    }).catch(() => {
      fallbackCopy(text, msg);
    });
  } else {
    fallbackCopy(text, msg);
  }
}

function fallbackCopy(text, msg) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    showToast(msg, 'success');
  } catch (e) {
    showToast('Gagal mengakses clipboard browser', 'error');
  }
  document.body.removeChild(ta);
}

// File Exporter
function exportDataAsFile(filename, content, type = 'text/plain;charset=utf-8') {
  if (!content) {
    showToast('Konten kosong, tidak ada data untuk diekspor', 'warning');
    return;
  }
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Berkas disimpan: ${filename}`, 'success');
}

// View Routing & Persistence
function switchView(viewId) {
  state.activeView = viewId;
  document.querySelectorAll('.view-container').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  
  const targetView = document.getElementById(`view-${viewId}`);
  if (targetView) targetView.classList.add('active');
  
  const targetNav = document.querySelector(`.nav-item[data-view="${viewId}"]`);
  if (targetNav) targetNav.classList.add('active');

  // Close mobile sidebar if open
  const sidebar = document.querySelector('.app-sidebar');
  const overlay = document.querySelector('.sidebar-overlay');
  if (sidebar && sidebar.classList.contains('mobile-open')) {
    sidebar.classList.remove('mobile-open');
    if (overlay) overlay.classList.remove('active');
  }

  // Track recents
  if (viewId !== 'dashboard' && !state.recents.includes(viewId)) {
    state.recents.unshift(viewId);
    if (state.recents.length > 8) state.recents.pop();
    localStorage.setItem('cyberlab_recents', JSON.stringify(state.recents));
    renderRecents();
  }

  if (typeof addAuditLog === 'function') {
    addAuditLog(`Navigated to module workspace: ${viewId.toUpperCase()}`, 'info');
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleMobileSidebar() {
  const sidebar = document.querySelector('.app-sidebar');
  const overlay = document.querySelector('.sidebar-overlay');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('mobile-open');
  if (overlay) overlay.classList.toggle('active', isOpen);
}

function renderRecents() {
  const container = document.getElementById('recent-tools-list');
  if (!container) return;
  if (!state.recents || state.recents.length === 0) {
    container.innerHTML = '<span class="empty-hint">Belum ada modul yang dibuka. Klik salah satu modul di bawah untuk memulai.</span>';
    return;
  }
  const viewNames = {
    'crypto': '1. Cryptography',
    'forensics': '2. Digital Forensics',
    'stego': '3. Steganography',
    'web': '4. Web Exploitation',
    'rev': '5. Reverse Engineering',
    'pwn': '6. Pwn & Exploit Lab',
    'osint': '7. OSINT Reconnaissance',
    'misc': '8. Miscellaneous Utilities',
    'pipeline': 'Tool Chaining Pipeline',
    'ctf-workspace': 'CTF Workspace Notes',
    'cheatsheets': 'Security References'
  };
  container.innerHTML = state.recents.map(id => `
    <button class="recent-chip" onclick="switchView('${id}')">
      ${viewNames[id] || id}
    </button>
  `).join('');
}

// UTF-8 Safe Base64 Helpers
const UTF8 = {
  encodeBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin);
  },
  decodeBase64(b64) {
    const clean = b64.trim().replace(/[\r\n\s]/g, '');
    const bin = atob(clean);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  },
  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },
  hexToBytes(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(Math.floor(clean.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }
};

// ============================================================================
// MODULE 1: CRYPTOGRAPHY ENGINE
// ============================================================================
const CryptoEngine = {
  caesar(str, shift, decrypt = false) {
    const s = decrypt ? ((26 - (shift % 26)) % 26) : (((shift % 26) + 26) % 26);
    return str.replace(/[a-zA-Z]/g, c => {
      const code = c.charCodeAt(0);
      const base = code >= 65 && code <= 90 ? 65 : 97;
      return String.fromCharCode(((code - base + s) % 26) + base);
    });
  },

  rot13(str) {
    return this.caesar(str, 13);
  },

  rot47(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code >= 33 && code <= 126) {
        out.push(String.fromCharCode(((code - 33 + 47) % 94) + 33));
      } else {
        out.push(str[i]);
      }
    }
    return out.join('');
  },

  atbash(str) {
    return str.replace(/[a-zA-Z]/g, c => {
      const code = c.charCodeAt(0);
      const isUpper = code >= 65 && code <= 90;
      const base = isUpper ? 65 : 97;
      return String.fromCharCode(base + (25 - (code - base)));
    });
  },

  vigenere(str, key, decrypt = false) {
    if (!key) return str;
    const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (!cleanKey) return str;
    let out = '';
    let ki = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      const code = c.charCodeAt(0);
      const isUpper = code >= 65 && code <= 90;
      const isLower = code >= 97 && code <= 122;
      if (isUpper || isLower) {
        const base = isUpper ? 65 : 97;
        const kShift = cleanKey.charCodeAt(ki % cleanKey.length) - 65;
        const shift = decrypt ? (26 - kShift) % 26 : kShift;
        out += String.fromCharCode(((code - base + shift) % 26) + base);
        ki++;
      } else {
        out += c;
      }
    }
    return out;
  },

  morse: {
    map: {
      'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
      'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
      'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
      'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
      'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
      '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
      '9': '----.', '0': '-----', ' ': '/'
    },
    encode(text) {
      return text.toUpperCase().trim().split('').map(c => this.map[c] || c).join(' ');
    },
    decode(morseStr) {
      const inv = {};
      Object.keys(this.map).forEach(k => { inv[this.map[k]] = k; });
      return morseStr.trim().split(/\s+/).map(s => {
        if (s === '/' || s === '|') return ' ';
        return inv[s] || s;
      }).join('');
    }
  },

  // XOR Engine with single-byte and repeating-key support
  xorBytes(inputBytes, keyBytes) {
    if (!keyBytes || keyBytes.length === 0) return inputBytes;
    const res = new Uint8Array(inputBytes.length);
    for (let i = 0; i < inputBytes.length; i++) {
      res[i] = inputBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    return res;
  },

  // Math Crypto with BigInt (Precise 2048-bit support)
  gcd(a, b) {
    a = BigInt(a);
    b = BigInt(b);
    if (a < 0n) a = -a;
    if (b < 0n) b = -b;
    while (b !== 0n) {
      const t = b;
      b = a % b;
      a = t;
    }
    return a;
  },

  extEuclid(a, b) {
    a = BigInt(a);
    b = BigInt(b);
    let x0 = 1n, y0 = 0n, x1 = 0n, y1 = 1n;
    while (b !== 0n) {
      const q = a / b;
      const r = a % b;
      a = b;
      b = r;
      const x2 = x0 - q * x1;
      const y2 = y0 - q * y1;
      x0 = x1;
      x1 = x2;
      y0 = y1;
      y1 = y2;
    }
    return { gcd: a, x: x0, y: y0 };
  },

  modInverse(a, m) {
    a = BigInt(a);
    m = BigInt(m);
    const res = this.extEuclid(a, m);
    if (res.gcd !== 1n) return null;
    return ((res.x % m) + m) % m;
  },

  modPow(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);
    if (mod === 1n) return 0n;
    let res = 1n;
    base = ((base % mod) + mod) % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) res = (res * base) % mod;
      exp = exp / 2n;
      base = (base * base) % mod;
    }
    return res;
  },

  async hash(strOrBuffer, algo = 'SHA-256') {
    let buffer;
    if (typeof strOrBuffer === 'string') {
      buffer = new TextEncoder().encode(strOrBuffer);
    } else {
      buffer = strOrBuffer;
    }
    const hashBuf = await crypto.subtle.digest(algo, buffer);
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
};

// ============================================================================
// MODULE 2: DIGITAL FORENSICS ENGINE
// ============================================================================
const ForensicsEngine = {
  signatures: [
    { magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], ext: 'png', mime: 'image/png', desc: 'PNG Image' },
    { magic: [0xFF, 0xD8, 0xFF], ext: 'jpg', mime: 'image/jpeg', desc: 'JPEG Image' },
    { magic: [0x47, 0x49, 0x46, 0x38], ext: 'gif', mime: 'image/gif', desc: 'GIF Graphic' },
    { magic: [0x50, 0x4B, 0x03, 0x04], ext: 'zip', mime: 'application/zip', desc: 'ZIP Archive / DOCX / APK' },
    { magic: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], ext: '7z', mime: 'application/x-7z-compressed', desc: '7-Zip Archive' },
    { magic: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], ext: 'rar', mime: 'application/x-rar-compressed', desc: 'RAR Archive' },
    { magic: [0x1F, 0x8B, 0x08], ext: 'gz', mime: 'application/gzip', desc: 'GZIP Compressed Stream' },
    { magic: [0x42, 0x5A, 0x68], ext: 'bz2', mime: 'application/x-bzip2', desc: 'BZIP2 Compressed File' },
    { magic: [0x25, 0x50, 0x44, 0x46], ext: 'pdf', mime: 'application/pdf', desc: 'PDF Document' },
    { magic: [0x7F, 0x45, 0x4C, 0x46], ext: 'elf', mime: 'application/x-executable', desc: 'Linux ELF Binary' },
    { magic: [0x4D, 0x5A], ext: 'exe', mime: 'application/x-dosexec', desc: 'Windows PE / DOS Executable' },
    { magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00], ext: 'sqlite', mime: 'application/x-sqlite3', desc: 'SQLite 3 Database' },
    { magic: [0xD4, 0xC3, 0xB2, 0xA1], ext: 'pcap', mime: 'application/vnd.tcpdump.pcap', desc: 'PCAP Capture (Little Endian)' },
    { magic: [0xA1, 0xB2, 0xC3, 0xD4], ext: 'pcap', mime: 'application/vnd.tcpdump.pcap', desc: 'PCAP Capture (Big Endian)' },
    { magic: [0x0A, 0x0D, 0x0D, 0x0A], ext: 'pcapng', mime: 'application/x-pcapng', desc: 'PCAP-NG Packet Capture' },
    { magic: [0x00, 0x61, 0x73, 0x6D], ext: 'wasm', mime: 'application/wasm', desc: 'WebAssembly Binary' },
    { magic: [0xCA, 0xFE, 0xBA, 0xBE], ext: 'class', mime: 'application/java-vm', desc: 'Java Compiled Class' },
    { magic: [0x42, 0x4D], ext: 'bmp', mime: 'image/bmp', desc: 'BMP Bitmap Image' },
    { magic: [0x52, 0x49, 0x46, 0x46], ext: 'wav', mime: 'audio/wav', desc: 'RIFF Container (WAV / AVI / WebP)' },
    { magic: [0x4F, 0x67, 0x67, 0x53], ext: 'ogg', mime: 'audio/ogg', desc: 'Ogg Multimedia Container' },
    { magic: [0x66, 0x74, 0x79, 0x70], ext: 'mp4', mime: 'video/mp4', desc: 'MP4 Video Container' }
  ],

  detectSignature(bytes) {
    if (!bytes || bytes.length === 0) return { ext: 'bin', mime: 'application/octet-stream', desc: 'Empty Data' };
    
    // Check direct magic start
    for (const sig of this.signatures) {
      if (bytes.length < sig.magic.length) continue;
      let match = true;
      for (let i = 0; i < sig.magic.length; i++) {
        if (bytes[i] !== sig.magic[i]) {
          match = false;
          break;
        }
      }
      if (match) return sig;
    }

    // Check ftyp offset for MP4 (offset 4)
    if (bytes.length > 8 && bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
      return { ext: 'mp4', mime: 'video/mp4', desc: 'ISO Base Media / MP4' };
    }

    return { ext: 'bin', mime: 'application/octet-stream', desc: 'Unknown Binary Format' };
  },

  calculateEntropy(uint8Array) {
    if (!uint8Array || uint8Array.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < uint8Array.length; i++) {
      freq[uint8Array[i]]++;
    }
    let entropy = 0;
    const len = uint8Array.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  },

  extractStrings(uint8Array, minLen = 4) {
    const results = [];
    let cur = [];
    for (let i = 0; i < uint8Array.length; i++) {
      const b = uint8Array[i];
      if (b >= 32 && b <= 126) {
        cur.push(String.fromCharCode(b));
      } else {
        if (cur.length >= minLen) {
          results.push(cur.join(''));
        }
        cur = [];
      }
    }
    if (cur.length >= minLen) results.push(cur.join(''));
    return results;
  },

  generateHexDump(uint8Array, maxBytes = 4096) {
    if (!uint8Array || uint8Array.length === 0) {
      return '<div class="hex-empty">Belum ada data biner yang dimuat.</div>';
    }
    const lines = [];
    const limit = Math.min(uint8Array.length, maxBytes);
    for (let i = 0; i < limit; i += 16) {
      const chunk = uint8Array.subarray(i, Math.min(i + 16, uint8Array.length));
      const offset = i.toString(16).padStart(8, '0');
      let hexPart = '';
      let asciiPart = '';
      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          const val = chunk[j];
          hexPart += val.toString(16).padStart(2, '0') + ' ';
          asciiPart += (val >= 32 && val <= 126) ? String.fromCharCode(val) : '.';
        } else {
          hexPart += '   ';
        }
        if (j === 7) hexPart += ' ';
      }
      lines.push(`<div class="hex-line"><span class="hex-offset">${offset}</span><span class="hex-bytes">${hexPart}</span><span class="hex-ascii">|${asciiPart}|</span></div>`);
    }
    if (uint8Array.length > maxBytes) {
      lines.push(`<div class="hex-truncated">[+ ${uint8Array.length - maxBytes} bytes lainnya disembunyikan untuk menjaga performa tampilan]</div>`);
    }
    return lines.join('');
  }
};

// ============================================================================
// MODULE 3: STEGANOGRAPHY ENGINE (STEGSOLVE-STYLE CANVAS BITPLANE)
// ============================================================================
const StegoEngine = {
  // Render visual 1-bit black & white plane on Canvas
  renderBitplane(sourceCanvas, targetCanvas, channelIndex = 0, bitPlane = 0) {
    const ctxSrc = sourceCanvas.getContext('2d');
    const w = sourceCanvas.width;
    const h = sourceCanvas.height;
    const imgData = ctxSrc.getImageData(0, 0, w, h);
    const data = imgData.data;

    targetCanvas.width = w;
    targetCanvas.height = h;
    const ctxTarget = targetCanvas.getContext('2d');
    const outImgData = ctxTarget.createImageData(w, h);
    const outData = outImgData.data;

    const mask = 1 << bitPlane;

    for (let i = 0; i < data.length; i += 4) {
      const pixelVal = data[i + channelIndex];
      const isBitOne = (pixelVal & mask) !== 0;
      const shade = isBitOne ? 255 : 0;
      outData[i] = shade;     // R
      outData[i + 1] = shade; // G
      outData[i + 2] = shade; // B
      outData[i + 3] = 255;   // A
    }

    ctxTarget.putImageData(outImgData, 0, 0);
  },

  // Extract LSB bitstream to text and raw bytes
  extractLSB(imgData, channelIndex = 0, bitPlane = 0, maxBytes = 4096) {
    const data = imgData.data;
    const mask = 1 << bitPlane;
    const totalBits = Math.floor(data.length / 4);
    const bytesCount = Math.min(Math.floor(totalBits / 8), maxBytes);
    const bytes = new Uint8Array(bytesCount);

    let byteIdx = 0;
    let bitAccum = 0;
    let bitCount = 0;

    for (let i = 0; i < data.length && byteIdx < bytesCount; i += 4) {
      const val = data[i + channelIndex];
      const bit = (val & mask) ? 1 : 0;
      bitAccum = (bitAccum << 1) | bit;
      bitCount++;
      if (bitCount === 8) {
        bytes[byteIdx++] = bitAccum;
        bitAccum = 0;
        bitCount = 0;
      }
    }

    let preview = '';
    for (let i = 0; i < Math.min(bytes.length, 1024); i++) {
      const b = bytes[i];
      preview += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
    }

    return {
      bitsAnalyzed: data.length / 4,
      extractedBytes: bytes.length,
      preview,
      rawBytes: bytes
    };
  }
};

// ============================================================================
// MODULE 4: WEB EXPLOITATION TOOLS
// ============================================================================
const WebEngine = {
  parseJWT(token) {
    if (!token || typeof token !== 'string') return { error: 'Token JWT kosong.' };
    const parts = token.trim().split('.');
    if (parts.length < 2) return { error: 'Struktur JWT tidak valid (kurang dari 2 segmen).' };
    try {
      const decodeUrlB64 = (str) => {
        let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        return UTF8.decodeBase64(b64);
      };

      const header = JSON.parse(decodeUrlB64(parts[0]));
      const payload = JSON.parse(decodeUrlB64(parts[1]));
      const signature = parts[2] || '';

      let expStatus = 'No expiration claim';
      if (payload.exp) {
        const expTime = new Date(payload.exp * 1000);
        const now = new Date();
        const diff = Math.round((expTime - now) / 1000);
        expStatus = diff > 0 ? `Valid (Kedaluwarsa dalam ${diff} detik, ${expTime.toISOString()})` : `EXPIRED (${Math.abs(diff)} detik lalu, ${expTime.toISOString()})`;
      }

      return { header, payload, signature, expStatus };
    } catch (e) {
      return { error: 'Gagal mendecode payload JWT: ' + e.message };
    }
  },

  auditSecurityHeaders(rawHeaders) {
    if (!rawHeaders || !rawHeaders.trim()) {
      return [{ status: 'warning', text: 'Ketik atau tempel HTTP response headers untuk memulai audit.' }];
    }
    const lines = rawHeaders.split('\n');
    const headerMap = {};
    for (const line of lines) {
      const idx = line.indexOf(':');
      if (idx !== -1) {
        const k = line.substring(0, idx).trim().toLowerCase();
        const v = line.substring(idx + 1).trim();
        headerMap[k] = v;
      }
    }

    const checklist = [
      { name: 'content-security-policy', desc: 'Content-Security-Policy (CSP)', rec: 'Membatasi sumber script dan proteksi XSS/Injection.' },
      { name: 'strict-transport-security', desc: 'Strict-Transport-Security (HSTS)', rec: 'Memaksa HTTPS dan mencegah SSL-stripping.' },
      { name: 'x-frame-options', desc: 'X-Frame-Options', rec: 'Mencegah serangan framing dan Clickjacking.' },
      { name: 'x-content-type-options', desc: 'X-Content-Type-Options (nosniff)', rec: 'Mencegah MIME-sniffing payload berkas berbahaya.' },
      { name: 'referrer-policy', desc: 'Referrer-Policy', rec: 'Mengontrol kebocoran URL sensitif pada request rujukan.' },
      { name: 'permissions-policy', desc: 'Permissions-Policy', rec: 'Membatasi akses sensor, kamera, mikrofon, dan geolocation.' }
    ];

    const findings = [];
    for (const item of checklist) {
      if (headerMap[item.name]) {
        findings.push({ status: 'pass', title: item.desc, value: headerMap[item.name] });
      } else {
        findings.push({ status: 'missing', title: item.desc, advice: item.rec });
      }
    }
    return findings;
  }
};

// ============================================================================
// MODULE 5: STATIC REVERSE ENGINEERING ENGINE
// ============================================================================
const RevEngine = {
  // Parse Linux ELF (ELF32 / ELF64) binary headers
  parseELF(bytes) {
    if (!bytes || bytes.length < 52) {
      return { error: 'Ukuran berkas terlalu kecil untuk format ELF header valid.' };
    }
    // Check Magic: 7F 45 4C 46
    if (bytes[0] !== 0x7F || bytes[1] !== 0x45 || bytes[2] !== 0x4C || bytes[3] !== 0x46) {
      return { error: 'Magic bytes bukan Linux ELF (0x7F454C46).' };
    }

    const is64 = bytes[4] === 2;
    const isLittleEndian = bytes[5] === 1;
    const osAbiMap = {
      0: 'System V', 1: 'HP-UX', 2: 'NetBSD', 3: 'Linux', 6: 'Solaris', 9: 'FreeBSD', 12: 'OpenBSD'
    };
    const osAbi = osAbiMap[bytes[7]] || `Custom (0x${bytes[7].toString(16)})`;

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const elfType = view.getUint16(16, isLittleEndian);
    const elfTypeMap = {
      1: 'ET_REL (Relocatable object)',
      2: 'ET_EXEC (Executable binary)',
      3: 'ET_DYN (Shared object / PIE Position-Independent Executable)',
      4: 'ET_CORE (Core dump)'
    };

    const machine = view.getUint16(18, isLittleEndian);
    const machineMap = {
      0x03: 'x86 (Intel 80386)',
      0x3E: 'x86-64 (AMD64)',
      0x28: 'ARM (32-bit)',
      0xB7: 'AArch64 (ARM 64-bit)',
      0xF3: 'RISC-V'
    };

    let entryPoint = 0n;
    let phOff = 0n;
    let shOff = 0n;

    if (is64) {
      entryPoint = view.getBigUint64(24, isLittleEndian);
      phOff = view.getBigUint64(32, isLittleEndian);
      shOff = view.getBigUint64(40, isLittleEndian);
    } else {
      entryPoint = BigInt(view.getUint32(24, isLittleEndian));
      phOff = BigInt(view.getUint32(28, isLittleEndian));
      shOff = BigInt(view.getUint32(32, isLittleEndian));
    }

    const shNumOffset = is64 ? 60 : 48;
    const shNum = bytes.length >= shNumOffset + 2 ? view.getUint16(shNumOffset, isLittleEndian) : 0;

    return {
      type: 'ELF',
      bitness: is64 ? '64-bit' : '32-bit',
      endianness: isLittleEndian ? 'Little Endian' : 'Big Endian',
      osAbi,
      category: elfTypeMap[elfType] || `Type 0x${elfType.toString(16)}`,
      architecture: machineMap[machine] || `Unknown Arch (0x${machine.toString(16)})`,
      entryPoint: '0x' + entryPoint.toString(16),
      programHeaderOffset: '0x' + phOff.toString(16),
      sectionHeaderOffset: '0x' + shOff.toString(16),
      sectionCount: shNum
    };
  },

  // Parse Windows PE (Portable Executable) binary headers
  parsePE(bytes) {
    if (!bytes || bytes.length < 64) {
      return { error: 'Berkas terlalu kecil untuk format Windows PE/DOS header.' };
    }
    // Check MZ: 0x4D, 0x5A
    if (bytes[0] !== 0x4D || bytes[1] !== 0x5A) {
      return { error: 'Magic bytes bukan DOS MZ (0x4D5A).' };
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const peOffset = view.getUint32(60, true);

    if (peOffset + 24 > bytes.length) {
      return { error: 'Offset PE Header (e_lfanew) melebihi batas panjang berkas.' };
    }

    // Check PE Signature: 0x50, 0x45, 0x00, 0x00
    if (bytes[peOffset] !== 0x50 || bytes[peOffset + 1] !== 0x45 || bytes[peOffset + 2] !== 0x00 || bytes[peOffset + 3] !== 0x00) {
      return { error: 'Signature PE tidak ditemukan pada offset yang ditunjuk.' };
    }

    const machine = view.getUint16(peOffset + 4, true);
    const machineMap = {
      0x014c: 'Intel 386 (x86 32-bit)',
      0x8664: 'AMD64 (x64 64-bit)',
      0xaa64: 'ARM64 Little Endian'
    };

    const sectionCount = view.getUint16(peOffset + 6, true);
    const timestamp = view.getUint32(peOffset + 8, true);
    const optHeaderSize = view.getUint16(peOffset + 20, true);

    let entryPoint = 'N/A';
    let imageBase = 'N/A';
    let subsystem = 'N/A';

    if (optHeaderSize > 0 && peOffset + 24 + optHeaderSize <= bytes.length) {
      const optMagic = view.getUint16(peOffset + 24, true);
      const isPE32Plus = optMagic === 0x20b;
      const epRva = view.getUint32(peOffset + 40, true);
      entryPoint = '0x' + epRva.toString(16);

      if (isPE32Plus) {
        imageBase = '0x' + view.getBigUint64(peOffset + 48, true).toString(16);
      } else {
        imageBase = '0x' + view.getUint32(peOffset + 52, true).toString(16);
      }

      const subVal = view.getUint16(peOffset + 92, true);
      const subMap = { 1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI (Console)', 7: 'POSIX CUI' };
      subsystem = subMap[subVal] || `Subsystem 0x${subVal.toString(16)}`;
    }

    // Extract section names
    const sections = [];
    let secTableStart = peOffset + 24 + optHeaderSize;
    for (let i = 0; i < Math.min(sectionCount, 16); i++) {
      const secOffset = secTableStart + (i * 40);
      if (secOffset + 40 <= bytes.length) {
        let name = '';
        for (let c = 0; c < 8; c++) {
          const ch = bytes[secOffset + c];
          if (ch === 0) break;
          name += String.fromCharCode(ch);
        }
        const virtSize = view.getUint32(secOffset + 8, true);
        const virtAddr = view.getUint32(secOffset + 12, true);
        sections.push(`${name || 'sec' + i} (RVA: 0x${virtAddr.toString(16)}, Size: 0x${virtSize.toString(16)})`);
      }
    }

    return {
      type: 'PE',
      architecture: machineMap[machine] || `Machine 0x${machine.toString(16)}`,
      sectionCount,
      timestamp: new Date(timestamp * 1000).toISOString(),
      entryPointRVA: entryPoint,
      imageBase,
      subsystem,
      sections
    };
  }
};

// ============================================================================
// MODULE 6: PWN & EXPLOIT LAB (DE BRUIJN CYCLIC SEQUENCE & OFFSETS)
// ============================================================================
const PwnEngine = {
  // True 4-tuple De Bruijn Cyclic Sequence Generator (standard pwntools compatible)
  generateDeBruijn(length = 256) {
    const k = 26; // Alphabet a-z
    const n = 4;  // 4-byte cycle
    const a = new Array(k * n).fill(0);
    const sequence = [];

    function db(t, p) {
      if (t > n) {
        if (n % p === 0) {
          for (let i = 1; i <= p; i++) {
            sequence.push(a[i]);
          }
        }
      } else {
        a[t] = a[t - p];
        db(t + 1, p);
        for (let j = a[t - p] + 1; j < k; j++) {
          a[t] = j;
          db(t + 1, t);
        }
      }
    }

    db(1, 1);

    let pattern = '';
    for (let i = 0; i < sequence.length && pattern.length < length; i++) {
      pattern += String.fromCharCode(97 + sequence[i]);
    }
    return pattern.slice(0, length);
  },

  // Offset Finder from substring or register crash address
  findOffset(pattern, searchVal) {
    if (!pattern || !searchVal) return { error: 'Pattern atau nilai pencarian kosong.' };
    let clean = searchVal.trim();

    // Check if input is hex representation (e.g. 0x61616164 or 61616164)
    if (clean.startsWith('0x') || /^[0-9a-fA-F]{8}$/.test(clean)) {
      const hex = clean.replace(/^0x/, '');
      if (hex.length % 2 === 0) {
        // Little-Endian decode
        let asciiLE = '';
        for (let i = hex.length - 2; i >= 0; i -= 2) {
          asciiLE += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        // Big-Endian decode
        let asciiBE = '';
        for (let i = 0; i < hex.length; i += 2) {
          asciiBE += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }

        const idxLE = pattern.indexOf(asciiLE);
        if (idxLE !== -1) {
          return {
            offset: idxLE,
            matchedString: asciiLE,
            endianness: 'Little-Endian ($RBP / $RIP standard)'
          };
        }

        const idxBE = pattern.indexOf(asciiBE);
        if (idxBE !== -1) {
          return {
            offset: idxBE,
            matchedString: asciiBE,
            endianness: 'Big-Endian'
          };
        }
      }
    }

    // Direct string search
    const idx = pattern.indexOf(clean);
    if (idx !== -1) {
      return {
        offset: idx,
        matchedString: clean,
        endianness: 'Direct Substring Match'
      };
    }

    return { error: `Nilai "${searchVal}" tidak ditemukan dalam cyclic pattern yang sedang aktif.` };
  }
};

// ============================================================================
// MODULE 7: OSINT RECONNAISSANCE (PRECISE CIDR CALCULATOR)
// ============================================================================
const OsintEngine = {
  // Complete IPv4 CIDR Calculator
  calcCIDR(cidrStr) {
    const parts = cidrStr.trim().split('/');
    if (parts.length !== 2) return { error: 'Format harus berupa IP/Prefix (contoh: 192.168.1.0/24).' };

    const ipParts = parts[0].trim().split('.');
    if (ipParts.length !== 4) return { error: 'Alamat IPv4 tidak valid (harus 4 oktet).' };

    let ipNum = 0;
    for (let i = 0; i < 4; i++) {
      const octet = parseInt(ipParts[i], 10);
      if (isNaN(octet) || octet < 0 || octet > 255) return { error: `Oktet #${i + 1} (${ipParts[i]}) tidak valid (rentang 0-255).` };
      ipNum = (ipNum << 8) | octet;
    }
    // unsigned conversion
    ipNum = ipNum >>> 0;

    const prefix = parseInt(parts[1], 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return { error: 'Prefix CIDR harus berada di antara rentang /0 sampai /32.' };

    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const netId = (ipNum & mask) >>> 0;
    const broadcast = (netId | ~mask) >>> 0;

    const numToIp = (n) => [
      (n >>> 24) & 255,
      (n >>> 16) & 255,
      (n >>> 8) & 255,
      n & 255
    ].join('.');

    const totalHosts = prefix === 32 ? 1 : Math.pow(2, 32 - prefix);
    const usableHosts = prefix >= 31 ? 0 : totalHosts - 2;
    const firstIp = prefix >= 31 ? 'N/A' : numToIp(netId + 1);
    const lastIp = prefix >= 31 ? 'N/A' : numToIp(broadcast - 1);

    const firstOctet = (ipNum >>> 24) & 255;
    let ipClass = 'Unknown';
    if (firstOctet >= 1 && firstOctet <= 126) ipClass = 'Class A';
    else if (firstOctet === 127) ipClass = 'Loopback';
    else if (firstOctet >= 128 && firstOctet <= 191) ipClass = 'Class B';
    else if (firstOctet >= 192 && firstOctet <= 223) ipClass = 'Class C';
    else if (firstOctet >= 224 && firstOctet <= 239) ipClass = 'Class D (Multicast)';
    else if (firstOctet >= 240 && firstOctet <= 255) ipClass = 'Class E (Experimental)';

    let ipScope = 'Public Routable';
    if ((firstOctet === 10) ||
        (firstOctet === 172 && ((ipNum >>> 16) & 255) >= 16 && ((ipNum >>> 16) & 255) <= 31) ||
        (firstOctet === 192 && ((ipNum >>> 16) & 255) === 168)) {
      ipScope = 'Private RFC 1918';
    } else if (firstOctet === 127) {
      ipScope = 'Loopback RFC 1122';
    }

    return {
      ip: numToIp(ipNum),
      prefix,
      netmask: numToIp(mask),
      wildcard: numToIp((~mask) >>> 0),
      networkAddress: numToIp(netId),
      broadcastAddress: numToIp(broadcast),
      firstUsableIp: firstIp,
      lastUsableIp: lastIp,
      totalAddresses: totalHosts.toLocaleString(),
      usableHosts: usableHosts.toLocaleString(),
      ipClass,
      ipScope
    };
  }
};

// ============================================================================
// MODULE 8: MISCELLANEOUS & BITWISE ENGINE (BIGINT AWARE)
// ============================================================================
const MiscEngine = {
  parseAnyInteger(val) {
    if (!val) return 0n;
    const s = String(val).trim().toLowerCase();
    try {
      if (s.startsWith('0x')) return BigInt(s);
      if (s.startsWith('0b')) return BigInt(s);
      if (s.startsWith('0o')) return BigInt(s);
      return BigInt(s);
    } catch (e) {
      return 0n;
    }
  },

  calcBitwise(aStr, op, bStr) {
    const a = this.parseAnyInteger(aStr);
    const b = this.parseAnyInteger(bStr);
    let res = 0n;

    if (op === 'AND') res = a & b;
    else if (op === 'OR') res = a | b;
    else if (op === 'XOR') res = a ^ b;
    else if (op === 'NOT_A') res = ~a;
    else if (op === 'SHL') res = a << (b > 1024n ? 1024n : b);
    else if (op === 'SHR') res = a >> (b > 1024n ? 1024n : b);

    return {
      dec: res.toString(10),
      hex: '0x' + (res < 0n ? (BigInt.asUintN(64, res)).toString(16) : res.toString(16)),
      bin: '0b' + (res < 0n ? (BigInt.asUintN(64, res)).toString(2) : res.toString(2))
    };
  }
};

// ============================================================================
// DASHBOARD WIDGETS: CLOCK, SCRATCHPAD & AUDIT LOG SYSTEM
// ============================================================================
let auditLogs = [
  { time: new Date().toLocaleTimeString('id-ID'), tag: 'info', msg: 'CyberLab Workstation initialized in client memory.' },
  { time: new Date().toLocaleTimeString('id-ID'), tag: 'success', msg: 'All 8 core analysis engines ready & armed.' },
  { time: new Date().toLocaleTimeString('id-ID'), tag: 'info', msg: 'Loaded 21 magic bytes signatures into registry.' }
];

function renderAuditLog() {
  const container = document.getElementById('dashboard-audit-log');
  if (!container) return;
  container.innerHTML = auditLogs.map(log => `
    <div class="audit-entry">
      <span class="audit-time">[${log.time}]</span>
      <span class="audit-tag ${log.tag}">${log.tag.toUpperCase()}</span>
      <span class="audit-msg">${escapeHtml(log.msg)}</span>
    </div>
  `).join('');
  container.scrollTop = container.scrollHeight;
}

function addAuditLog(msg, tag = 'info') {
  const now = new Date();
  const timeStr = now.toLocaleTimeString('id-ID', { hour12: false });
  auditLogs.push({ time: timeStr, tag, msg });
  if (auditLogs.length > 50) auditLogs.shift();
  renderAuditLog();
}

function clearAuditLog() {
  auditLogs = [{ time: new Date().toLocaleTimeString('id-ID'), tag: 'info', msg: 'Audit log cleared.' }];
  renderAuditLog();
  showToast('Log operasi berhasil dibersihkan.', 'info');
}

function initDashboardWidgets() {
  // 1. Live Session Clock & Timer
  const sessionStart = Date.now();
  const clockEl = document.getElementById('live-session-clock');
  const timerEl = document.getElementById('live-session-timer');

  function updateClock() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const mins = String(now.getMinutes()).padStart(2, '0');
    const secs = String(now.getSeconds()).padStart(2, '0');
    if (clockEl) clockEl.textContent = `${hours}:${mins}:${secs} WIB`;

    const diff = Math.floor((Date.now() - sessionStart) / 1000);
    const th = String(Math.floor(diff / 3600)).padStart(2, '0');
    const tm = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
    const ts = String(diff % 60).padStart(2, '0');
    if (timerEl) timerEl.textContent = `Investigasi berjalan: ${th}:${tm}:${ts}`;
  }
  updateClock();
  setInterval(updateClock, 1000);

  // 2. Scratchpad Auto-load & Auto-save
  const scratchpad = document.getElementById('dashboard-scratchpad');
  const charCount = document.getElementById('scratchpad-char-count');
  const statusEl = document.getElementById('scratchpad-status');

  if (scratchpad) {
    const saved = localStorage.getItem('cyberlab_scratchpad');
    if (saved) {
      scratchpad.value = saved;
      if (charCount) charCount.textContent = `${saved.length} karakter`;
    }

    let saveTimeout = null;
    scratchpad.addEventListener('input', () => {
      const len = scratchpad.value.length;
      if (charCount) charCount.textContent = `${len} karakter`;
      if (statusEl) statusEl.textContent = 'Menyimpan...';

      clearTimeout(saveTimeout);
      saveTimeout = setTimeout(() => {
        localStorage.setItem('cyberlab_scratchpad', scratchpad.value);
        if (statusEl) statusEl.textContent = 'Tersimpan otomatis ke LocalStorage';
      }, 500);
    });
  }

  // 3. Render initial audit logs
  renderAuditLog();
}

function insertFlagTemplate() {
  const pad = document.getElementById('dashboard-scratchpad');
  if (!pad) return;
  const tpl = `\nLKS{flag_here_}\n`;
  pad.value += tpl;
  pad.dispatchEvent(new Event('input'));
  pad.focus();
  showToast('Format flag ditambahkan ke scratchpad.', 'success');
  addAuditLog('Flag template snippet inserted into scratchpad.', 'info');
}

function copyScratchpad() {
  const pad = document.getElementById('dashboard-scratchpad');
  if (!pad || !pad.value.trim()) {
    showToast('Scratchpad masih kosong.', 'warning');
    return;
  }
  navigator.clipboard.writeText(pad.value).then(() => {
    showToast('Catatan scratchpad disalin ke clipboard.', 'success');
    addAuditLog(`Copied ${pad.value.length} characters from scratchpad.`, 'info');
  });
}

function clearScratchpad() {
  const pad = document.getElementById('dashboard-scratchpad');
  if (!pad) return;
  if (!pad.value.trim()) return;
  pad.value = '';
  pad.dispatchEvent(new Event('input'));
  showToast('Scratchpad dikosongkan.', 'info');
  addAuditLog('Scratchpad cleared by user.', 'info');
}

function copyRefText(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`Nilai referensi disalin: ${text.slice(0, 30)}...`, 'success');
    addAuditLog(`Copied quick reference: ${text.slice(0, 35)}`, 'info');
  });
}

// ============================================================================
// INITIALIZATION ON DOM READY
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  renderRecents();
  initDashboardWidgets();

  // Global search tool filtering
  const searchInput = document.getElementById('global-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      const cards = document.querySelectorAll('.category-card');
      let matches = 0;
      cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        const isMatch = text.includes(q);
        card.style.display = isMatch ? 'flex' : 'none';
        if (isMatch) matches++;
      });
      const emptyState = document.getElementById('search-empty-state');
      if (emptyState) {
        emptyState.style.display = (matches === 0 && q.length > 0) ? 'block' : 'none';
      }
    });
  }

  // Keyboard shortcut Ctrl+K
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      searchInput?.focus();
    }
    if (e.key === 'Escape') {
      closeAutoTriageModal();
    }
  });

  // Pre-load saved notes
  const notesArea = document.getElementById('ctf-workspace-notes');
  if (notesArea && state.notes) {
    notesArea.value = state.notes;
  }
});
