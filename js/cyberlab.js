/**
 * CyberLab LKS - Core Engine & Tool Registry
 * High-performance, client-side, zero-telemetry cybersecurity toolkit.
 */

// Global State
const state = {
  activeView: 'dashboard',
  activeCryptoTab: 'classical',
  activeForensicsTab: 'file-analyzer',
  activeStegoTab: 'image-analyzer',
  activeWebTab: 'http-analyzer',
  activeRevTab: 'binary-id',
  activePwnTab: 'binary-info',
  activeOsintTab: 'domain-analysis',
  activeMiscTab: 'text-tools',
  favorites: JSON.parse(localStorage.getItem('cyberlab_favorites') || '[]'),
  recents: JSON.parse(localStorage.getItem('cyberlab_recents') || '[]'),
  notes: localStorage.getItem('cyberlab_notes') || '',
  pipeline: []
};

// UI Helper: Toast
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';
  if (type === 'warning') icon = '⚠️';
  
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

// Clipboard helper
function copyToClipboard(text, msg = 'Tersalin ke clipboard!') {
  if (!text) {
    showToast('Tidak ada teks untuk disalin', 'warning');
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    showToast(msg, 'success');
  }).catch(() => {
    showToast('Gagal mengakses clipboard', 'error');
  });
}

// File Downloader / Exporter
function exportDataAsFile(filename, content, type = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Berkas diekspor: ${filename}`, 'success');
}

// Switch View
function switchView(viewId) {
  state.activeView = viewId;
  document.querySelectorAll('.view-container').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  
  const targetView = document.getElementById(`view-${viewId}`);
  if (targetView) targetView.classList.add('active');
  
  const targetNav = document.querySelector(`.nav-item[data-view="${viewId}"]`);
  if (targetNav) targetNav.classList.add('active');

  // Track recents
  if (viewId !== 'dashboard' && !state.recents.includes(viewId)) {
    state.recents.unshift(viewId);
    if (state.recents.length > 8) state.recents.pop();
    localStorage.setItem('cyberlab_recents', JSON.stringify(state.recents));
    renderRecents();
  }
}

// Render Recents in Dashboard
function renderRecents() {
  const container = document.getElementById('recent-tools-list');
  if (!container) return;
  if (state.recents.length === 0) {
    container.innerHTML = '<span style="color:#64748b;font-size:0.75rem;">Belum ada tool yang baru saja digunakan.</span>';
    return;
  }
  const viewNames = {
    'crypto': 'Cryptography Suite',
    'forensics': 'Digital Forensics',
    'stego': 'Steganography Toolkit',
    'web': 'Web Exploitation Labs',
    'rev': 'Reverse Engineering',
    'pwn': 'Pwn & Binary Exploitation',
    'osint': 'OSINT Reconnaissance',
    'misc': 'Miscellaneous Utilities',
    'pipeline': 'Tool Chaining Pipeline',
    'ctf-workspace': 'CTF Challenge Workspace',
    'cheatsheets': 'CTF & Security Cheatsheet'
  };
  container.innerHTML = state.recents.map(id => `
    <button class="quick-btn" onclick="switchView('${id}')">
      ⚡ ${viewNames[id] || id}
    </button>
  `).join('');
}

// -------------------------------------------------------------
// MODULE 1: CRYPTOGRAPHY ENGINE
// -------------------------------------------------------------
const CryptoEngine = {
  // Classical Ciphers
  caesar(str, shift, decrypt = false) {
    let s = decrypt ? (26 - (shift % 26)) % 26 : shift % 26;
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
    let out = [];
    for (let i = 0; i < str.length; i++) {
      let code = str.charCodeAt(i);
      if (code >= 33 && code <= 126) {
        out.push(String.fromCharCode(33 + ((code + 14) % 94)));
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
      return text.toUpperCase().split('').map(c => this.map[c] || c).join(' ');
    },
    decode(morseStr) {
      const inv = {};
      Object.keys(this.map).forEach(k => inv[this.map[k]] = k);
      return morseStr.split(' ').map(s => {
        if (s === '/' || s === '') return ' ';
        return inv[s] || s;
      }).join('');
    }
  },

  // XOR helpers
  xorSingleByte(hexOrText, keyByte, isHex = false) {
    let bytes = [];
    if (isHex) {
      const clean = hexOrText.replace(/[^0-9a-fA-F]/g, '');
      for (let i = 0; i < clean.length; i += 2) {
        bytes.push(parseInt(clean.substr(i, 2), 16));
      }
    } else {
      bytes = Array.from(new TextEncoder().encode(hexOrText));
    }
    const res = bytes.map(b => b ^ keyByte);
    const textOut = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(res));
    const hexOut = res.map(b => b.toString(16).padStart(2, '0')).join('');
    return { text: textOut, hex: hexOut };
  },

  // Math Crypto
  gcd(a, b) {
    a = BigInt(a);
    b = BigInt(b);
    while (b !== 0n) {
      let t = b;
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
      let q = a / b;
      let r = a % b;
      a = b;
      b = r;
      let x2 = x0 - q * x1;
      let y2 = y0 - q * y1;
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
    let res = this.extEuclid(a, m);
    if (res.gcd !== 1n) return null;
    let inv = (res.x % m + m) % m;
    return inv;
  },

  modPow(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) res = (res * base) % mod;
      exp = exp / 2n;
      base = (base * base) % mod;
    }
    return res;
  },

  isPrime(n) {
    n = BigInt(n);
    if (n <= 1n) return false;
    if (n <= 3n) return true;
    if (n % 2n === 0n || n % 3n === 0n) return false;
    for (let i = 5n; i * i <= n; i += 6n) {
      if (n % i === 0n || n % (i + 2n) === 0n) return false;
    }
    return true;
  },

  // Hash calculator via WebCrypto & pure JS
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

// -------------------------------------------------------------
// MODULE 2: DIGITAL FORENSICS ENGINE
// -------------------------------------------------------------
const ForensicsEngine = {
  // Magic Bytes signature database
  signatures: [
    { magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], ext: 'png', mime: 'image/png', desc: 'PNG Image File' },
    { magic: [0xFF, 0xD8, 0xFF], ext: 'jpg', mime: 'image/jpeg', desc: 'JPEG / JFIF Image' },
    { magic: [0x47, 0x49, 0x46, 0x38], ext: 'gif', mime: 'image/gif', desc: 'GIF Graphic File' },
    { magic: [0x50, 0x4B, 0x03, 0x04], ext: 'zip', mime: 'application/zip', desc: 'ZIP Archive / Office DOCX/APK' },
    { magic: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], ext: 'rar', mime: 'application/x-rar-compressed', desc: 'RAR Archive' },
    { magic: [0x25, 0x50, 0x44, 0x46], ext: 'pdf', mime: 'application/pdf', desc: 'PDF Document' },
    { magic: [0x7F, 0x45, 0x4C, 0x46], ext: 'elf', mime: 'application/x-executable', desc: 'Linux ELF Executable/Binary' },
    { magic: [0x4D, 0x5A], ext: 'exe', mime: 'application/x-dosexec', desc: 'Windows PE / DOS Executable' },
    { magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00], ext: 'sqlite', mime: 'application/x-sqlite3', desc: 'SQLite 3 Database' },
    { magic: [0xD4, 0xC3, 0xB2, 0xA1], ext: 'pcap', mime: 'application/vnd.tcpdump.pcap', desc: 'PCAP Packet Capture (Little Endian)' },
    { magic: [0xA1, 0xB2, 0xC3, 0xD4], ext: 'pcap', mime: 'application/vnd.tcpdump.pcap', desc: 'PCAP Packet Capture (Big Endian)' },
    { magic: [0x0A, 0x0D, 0x0D, 0x0A], ext: 'pcapng', mime: 'application/x-pcapng', desc: 'PCAP-NG Packet Capture' },
    { magic: [0x1F, 0x8B], ext: 'gz', mime: 'application/gzip', desc: 'GZIP Compressed File' }
  ],

  detectSignature(bytes) {
    for (const sig of this.signatures) {
      let match = true;
      for (let i = 0; i < sig.magic.length; i++) {
        if (bytes[i] !== sig.magic[i]) {
          match = false;
          break;
        }
      }
      if (match) return sig;
    }
    return { ext: 'bin', mime: 'application/octet-stream', desc: 'Unknown Binary / Raw Data' };
  },

  // Calculate Shannon Entropy (0.0 to 8.0)
  calculateEntropy(uint8Array) {
    if (!uint8Array || uint8Array.length === 0) return 0;
    const freq = new Array(256).fill(0);
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

  // Extract ASCII and Unicode printable strings
  extractStrings(uint8Array, minLen = 4) {
    let results = [];
    let current = [];
    for (let i = 0; i < uint8Array.length; i++) {
      const b = uint8Array[i];
      if (b >= 32 && b <= 126) {
        current.push(String.fromCharCode(b));
      } else {
        if (current.length >= minLen) {
          results.push(current.join(''));
        }
        current = [];
      }
    }
    if (current.length >= minLen) results.push(current.join(''));
    return results;
  },

  // Format Hex dump
  generateHexDump(uint8Array, maxBytes = 4096) {
    let lines = [];
    const limit = Math.min(uint8Array.length, maxBytes);
    for (let i = 0; i < limit; i += 16) {
      const chunk = uint8Array.slice(i, i + 16);
      const offset = i.toString(16).padStart(8, '0');
      let hexPart = '';
      let asciiPart = '';
      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          hexPart += chunk[j].toString(16).padStart(2, '0') + ' ';
          asciiPart += (chunk[j] >= 32 && chunk[j] <= 126) ? String.fromCharCode(chunk[j]) : '.';
        } else {
          hexPart += '   ';
        }
        if (j === 7) hexPart += ' ';
      }
      lines.push(`<div class="hex-line"><span class="hex-offset">${offset}</span><span class="hex-bytes">${hexPart}</span><span class="hex-ascii">|${asciiPart}|</span></div>`);
    }
    if (uint8Array.length > maxBytes) {
      lines.push(`<div class="hex-line" style="color:#f59e0b;">... [+ ${uint8Array.length - maxBytes} bytes truncated for display performance]</div>`);
    }
    return lines.join('');
  }
};

// -------------------------------------------------------------
// MODULE 3: STEGANOGRAPHY ENGINE
// -------------------------------------------------------------
const StegoEngine = {
  // Extract LSB bit plane from ImageData
  extractLSB(imgData, channelIndex = 0, bitPlane = 0) {
    const data = imgData.data;
    let bits = [];
    for (let i = 0; i < data.length; i += 4) {
      const val = data[i + channelIndex];
      bits.push((val >> bitPlane) & 1);
    }
    // Convert bits to byte string
    let bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) {
        b = (b << 1) | bits[i + j];
      }
      bytes.push(b);
    }
    // Printable preview
    let preview = '';
    for (let i = 0; i < Math.min(bytes.length, 1024); i++) {
      const c = bytes[i];
      preview += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
    }
    return { bitsCount: bits.length, preview, rawBytes: new Uint8Array(bytes) };
  }
};

// -------------------------------------------------------------
// MODULE 4: WEB EXPLOITATION TOOLS
// -------------------------------------------------------------
const WebEngine = {
  parseJWT(token) {
    if (!token || !token.includes('.')) return null;
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;
    try {
      const decodeBase64Url = (str) => {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        return decodeURIComponent(escape(atob(base64)));
      };
      const header = JSON.parse(decodeBase64Url(parts[0]));
      const payload = JSON.parse(decodeBase64Url(parts[1]));
      return { header, payload, signature: parts[2] || '' };
    } catch (e) {
      return { error: 'Gagal mendecode format JWT: ' + e.message };
    }
  }
};

// -------------------------------------------------------------
// INITIALIZATION ON DOM READY
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  renderRecents();

  // Search filter
  const searchInput = document.getElementById('global-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      document.querySelectorAll('.category-card').forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? 'flex' : 'none';
      });
    });
  }

  // Hotkey Cmd+K or Ctrl+K for search
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      searchInput?.focus();
    }
  });

  console.log('⚡ CyberLab LKS Workstation Initialized.');
});
