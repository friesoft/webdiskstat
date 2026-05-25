let DATA = null;

function unpackReportData(payload) {
  const strings = payload[0] || [];
  const packedRoot = payload[1];

  function valueAt(index) {
    return index >= 0 ? strings[index] : "";
  }

  function joinNodePath(parentPath, name) {
    if (!parentPath) return name;
    if (parentPath === "/") return "/" + name.replace(/^\/+/, "");
    return parentPath.replace(/\/+$/, "") + "/" + name.replace(/^\/+/, "");
  }

  function decodeNode(packed, parentPath) {
    const name = valueAt(packed[0]);
    const path = packed[1] >= 0 ? valueAt(packed[1]) : joinNodePath(parentPath, name);
    const type = packed[3] ? "dir" : "file";
    const node = {
      name,
      path,
      size: packed[2] || 0,
      type,
      ext: valueAt(packed[4]) || (type === "dir" ? "" : "[no extension]"),
      children: []
    };
    const mtime = valueAt(packed[5]);
    const mime = valueAt(packed[6]);
    const flag = valueAt(packed[7]);
    if (mtime) node.mtime = mtime;
    if (mime) node.mime = mime;
    if (flag) node.flag = flag;
    node.children = (Array.isArray(packed[8]) ? packed[8] : []).map(child => decodeNode(child, path));
    return node;
  }

  return decodeNode(packedRoot, "");
}

function bytesFromBase64(value) {
  const binary = atob(value || "");
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function utf8Bytes(value) {
  return new TextEncoder().encode(value);
}

async function loadCompressedReportData(bytes) {
  if (typeof DecompressionStream !== "function") {
    throw new Error("This browser cannot decompress embedded report data. Use a current Chrome, Edge, Firefox, or Safari release.");
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const text = await new Response(stream).text();
  return unpackReportData(JSON.parse(text));
}

async function loadReportData(payload) {
  const compressed = payload && payload.encrypted
    ? await decryptReportPayload(payload)
    : bytesFromBase64(payload && payload.payload);
  return loadCompressedReportData(compressed);
}

async function decryptReportPayload(payload) {
  if (payload.algorithm !== "ChaCha20-Poly1305") {
    throw new Error(`Unsupported encrypted report algorithm: ${payload.algorithm || "unknown"}`);
  }
  if (payload.kdf !== "PBKDF2-SHA256") {
    throw new Error(`Unsupported encrypted report KDF: ${payload.kdf || "unknown"}`);
  }
  const iterations = Number(payload.iterations);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 5000000) {
    throw new Error("Encrypted report KDF parameters are invalid.");
  }

  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const promptText = attempt
      ? "Incorrect password. Try again:"
      : "Enter password to open this encrypted report:";
    const password = window.prompt(promptText);
    if (password === null) throw new Error("Password required to open encrypted report.");

    try {
      const key = await deriveReportKey(password, bytesFromBase64(payload.salt), iterations);
      return chacha20Poly1305Decrypt(
        key,
        bytesFromBase64(payload.nonce),
        bytesFromBase64(payload.payload),
        bytesFromBase64(payload.tag),
        utf8Bytes(payload.aad || "webdiskstat-report-data-v1")
      );
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error(lastError && lastError.message ? "Unable to decrypt report data. Check the password." : "Unable to decrypt report data.");
}

async function deriveReportKey(password, salt, iterations) {
  const passwordBytes = utf8Bytes(password);
  if (globalThis.crypto && crypto.subtle) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations
      },
      keyMaterial,
      256
    );
    return new Uint8Array(bits);
  }

  return pbkdf2Sha256(passwordBytes, salt, iterations, 32);
}

function pbkdf2Sha256(password, salt, iterations, length) {
  const hashLength = 32;
  const blockCount = Math.ceil(length / hashLength);
  const output = new Uint8Array(blockCount * hashLength);

  for (let block = 1; block <= blockCount; block++) {
    const saltBlock = new Uint8Array(salt.length + 4);
    saltBlock.set(salt);
    saltBlock[salt.length] = (block >>> 24) & 255;
    saltBlock[salt.length + 1] = (block >>> 16) & 255;
    saltBlock[salt.length + 2] = (block >>> 8) & 255;
    saltBlock[salt.length + 3] = block & 255;

    let u = hmacSha256(password, saltBlock);
    const t = new Uint8Array(u);
    for (let iteration = 1; iteration < iterations; iteration++) {
      u = hmacSha256(password, u);
      for (let index = 0; index < hashLength; index++) t[index] ^= u[index];
    }
    output.set(t, (block - 1) * hashLength);
  }

  return output.slice(0, length);
}

function hmacSha256(key, message) {
  let normalizedKey = key;
  if (normalizedKey.length > 64) normalizedKey = sha256(normalizedKey);

  const inner = new Uint8Array(64 + message.length);
  const outer = new Uint8Array(96);
  for (let index = 0; index < 64; index++) {
    const value = index < normalizedKey.length ? normalizedKey[index] : 0;
    inner[index] = value ^ 0x36;
    outer[index] = value ^ 0x5c;
  }
  inner.set(message, 64);
  outer.set(sha256(inner), 64);
  return sha256(outer);
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256(message) {
  const bitLength = BigInt(message.length) * 8n;
  const paddedLength = Math.ceil((message.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(message);
  padded[message.length] = 0x80;
  for (let index = 0; index < 8; index++) {
    padded[paddedLength - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 255n);
  }

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;
  const words = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let index = 0; index < 16; index++) {
      words[index] = readU32BE(padded, offset + index * 4);
    }
    for (let index = 16; index < 64; index++) {
      const s0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >>> 3);
      const s1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >>> 10);
      words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let index = 0; index < 64; index++) {
      const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA256_K[index] + words[index]) >>> 0;
      const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const digest = new Uint8Array(32);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((value, index) => writeU32BE(digest, index * 4, value));
  return digest;
}

function rotateRight(value, bits) {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

function readU32BE(bytes, offset) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function writeU32BE(bytes, offset, value) {
  bytes[offset] = (value >>> 24) & 255;
  bytes[offset + 1] = (value >>> 16) & 255;
  bytes[offset + 2] = (value >>> 8) & 255;
  bytes[offset + 3] = value & 255;
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad) {
  if (key.length !== 32 || nonce.length !== 12 || tag.length !== 16) {
    throw new Error("Encrypted report payload is malformed.");
  }
  const polyKey = chacha20Block(key, nonce, 0).slice(0, 32);
  const expectedTag = poly1305Mac(poly1305AeadData(aad, ciphertext), polyKey);
  if (!timingSafeEqual(tag, expectedTag)) {
    throw new Error("Decryption failed.");
  }
  return chacha20Xor(key, nonce, 1, ciphertext);
}

function chacha20Xor(key, nonce, counter, input) {
  const output = new Uint8Array(input.length);
  for (let offset = 0; offset < input.length; offset += 64) {
    const block = chacha20Block(key, nonce, counter);
    const length = Math.min(64, input.length - offset);
    for (let index = 0; index < length; index++) {
      output[offset + index] = input[offset + index] ^ block[index];
    }
    counter = (counter + 1) >>> 0;
    if (counter === 0 && offset + 64 < input.length) {
      throw new Error("Encrypted report payload is too large.");
    }
  }
  return output;
}

function chacha20Block(key, nonce, counter) {
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let index = 0; index < 8; index++) state[4 + index] = readU32(key, index * 4);
  state[12] = counter >>> 0;
  state[13] = readU32(nonce, 0);
  state[14] = readU32(nonce, 4);
  state[15] = readU32(nonce, 8);

  const working = new Uint32Array(state);
  for (let round = 0; round < 10; round++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const output = new Uint8Array(64);
  for (let index = 0; index < 16; index++) {
    writeU32(output, index * 4, (working[index] + state[index]) >>> 0);
  }
  return output;
}

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 7);
}

function rotateLeft(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function readU32(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function writeU32(bytes, offset, value) {
  bytes[offset] = value & 255;
  bytes[offset + 1] = (value >>> 8) & 255;
  bytes[offset + 2] = (value >>> 16) & 255;
  bytes[offset + 3] = (value >>> 24) & 255;
}

function poly1305AeadData(aad, ciphertext) {
  const aadPad = (16 - aad.length % 16) % 16;
  const ciphertextPad = (16 - ciphertext.length % 16) % 16;
  const data = new Uint8Array(aad.length + aadPad + ciphertext.length + ciphertextPad + 16);
  let offset = 0;
  data.set(aad, offset);
  offset += aad.length + aadPad;
  data.set(ciphertext, offset);
  offset += ciphertext.length + ciphertextPad;
  writeU64(data, offset, aad.length);
  writeU64(data, offset + 8, ciphertext.length);
  return data;
}

function poly1305Mac(message, key) {
  if (key.length !== 32) throw new Error("Poly1305 key is malformed.");
  const rBytes = key.slice(0, 16);
  rBytes[3] &= 15;
  rBytes[7] &= 15;
  rBytes[11] &= 15;
  rBytes[15] &= 15;
  rBytes[4] &= 252;
  rBytes[8] &= 252;
  rBytes[12] &= 252;

  const r = littleEndianToBigInt(rBytes);
  const s = littleEndianToBigInt(key.slice(16, 32));
  const modulus = (1n << 130n) - 5n;
  let accumulator = 0n;

  for (let offset = 0; offset < message.length; offset += 16) {
    const block = message.slice(offset, Math.min(offset + 16, message.length));
    const n = littleEndianToBigInt(block) + (1n << BigInt(block.length * 8));
    accumulator = ((accumulator + n) * r) % modulus;
  }

  return bigIntTo16Bytes((accumulator + s) & ((1n << 128n) - 1n));
}

function littleEndianToBigInt(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) + BigInt(bytes[index]);
  }
  return value;
}

function bigIntTo16Bytes(value) {
  const bytes = new Uint8Array(16);
  for (let index = 0; index < 16; index++) {
    bytes[index] = Number((value >> BigInt(index * 8)) & 255n);
  }
  return bytes;
}

function writeU64(bytes, offset, value) {
  let remaining = BigInt(value);
  for (let index = 0; index < 8; index++) {
    bytes[offset + index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
  return diff === 0;
}

const palette = [
  "#2563eb", "#0f766e", "#c2410c", "#7c3aed", "#be123c", "#047857",
  "#b45309", "#0369a1", "#a21caf", "#4d7c0f", "#b91c1c", "#1d4ed8",
  "#0e7490", "#9333ea", "#ca8a04", "#15803d", "#db2777", "#4338ca"
];
const TREEMAP_SMALLER_ENTRIES_COLOR = "#64748b";
const DEFAULT_TREEMAP_TILE_CAP = 5;
const TREEMAP_TILE_CAP_OPTIONS = [5, 10, 20, 50, 100];
const TREEMAP_MAX_DEPTH = 8;
const TREEMAP_CHILD_INSET = 4;
const TREEMAP_CHILD_LABEL_HEIGHT = 24;
const TREEMAP_MIN_NESTED_WIDTH = 92;
const TREEMAP_MIN_NESTED_HEIGHT = 68;
const TREEMAP_TOP_LEVEL_DIR_GAP = 2;
const TREE_ROW_HEIGHT = 36;
const TREE_OVERSCAN_ROWS = 8;
const TOP_FILES_LIMITS = [10, 20, 30, 40, 50];
const DEFAULT_TREE_COLUMNS = Object.freeze({
  items: true,
  files: true,
  size: true,
  modified: true,
  percent: true
});
const TREE_COLUMNS = [
  { key: "name", label: "Name", menuLabel: "Name", grid: "minmax(150px, 1fr)", minWidth: 260, required: true, sortKey: "name" },
  { key: "items", label: "Items", menuLabel: "Items", grid: "52px", minWidth: 52, numeric: true, sortKey: "items" },
  { key: "files", label: "Files", menuLabel: "Files", grid: "52px", minWidth: 52, numeric: true, sortKey: "files" },
  { key: "size", label: "Size", menuLabel: "Size", grid: "82px", minWidth: 82, numeric: true, sortKey: "size" },
  { key: "modified", label: "Modified", menuLabel: "Modified", grid: "126px", minWidth: 126, sortKey: "modified" },
  { key: "percent", label: "%", menuLabel: "Percent", grid: "46px", minWidth: 46, numeric: true }
];
const SORT_SHORTCUTS = new Map([
  ["n", "name"],
  ["s", "size"],
  ["C", "files"],
  ["M", "modified"],
  ["m", "modified"]
]);
const TREE_COLUMN_STORAGE_KEY = "webdiskstat-tree-columns";
const THEME_STORAGE_KEY = "webdiskstat-theme";
const TREEMAP_TILE_CAP_STORAGE_KEY = "webdiskstat-treemap-tile-cap";
const MAIN_PANE_STORAGE_KEY = "webdiskstat-sidebar-size";
const MAIN_MIN_SIDEBAR_SIZE = 280;
const MAIN_MIN_CONTENT_SIZE = 360;
const MAIN_RESIZER_SIZE = 10;
const MAIN_RESIZE_STEP = 32;
const HOME_TREEMAP_STORAGE_KEY = "webdiskstat-home-treemap-size";
const HOME_MIN_TREEMAP_SIZE = 180;
const HOME_MIN_TOP_FILES_SIZE = 260;
const HOME_RESIZER_SIZE = 12;
const HOME_RESIZE_STEP = 32;
const SEARCH_RESULT_LIMIT = 50;
const SEARCH_DEBOUNCE_MS = 80;
const SEARCH_TRIGRAM_SIZE = 3;

const state = {
  current: null,
  selected: null,
  sortKey: "size",
  sortDir: "desc",
  topFilesLimit: 10,
  treemapTileCap: DEFAULT_TREEMAP_TILE_CAP,
  searchActiveIndex: -1,
  visibleColumns: { ...DEFAULT_TREE_COLUMNS }
};

const byId = new Map();
const byPath = new Map();
const parent = new Map();
const searchIndex = [];
const searchCandidateIndex = new Map();
let searchResults = [];
let searchTimer = 0;
let nextNodeId = 0;
const treeView = {
  node: null,
  children: [],
  total: 0,
  body: null,
  start: -1,
  end: -1
};

const el = {
  crumbs: document.getElementById("crumbs"),
  themeToggle: document.getElementById("themeToggle"),
  helpButton: document.getElementById("helpButton"),
  helpPage: document.getElementById("helpPage"),
  helpCloseButton: document.getElementById("helpCloseButton"),
  searchShortcut: document.getElementById("searchShortcut"),
  searchInput: document.getElementById("searchInput"),
  searchResults: document.getElementById("searchResults"),
  selectedSize: document.getElementById("selectedSize"),
  selectedItems: document.getElementById("selectedItems"),
  selectedFiles: document.getElementById("selectedFiles"),
  main: document.getElementById("main"),
  sidebar: document.getElementById("sidebar"),
  mainResizer: document.getElementById("mainResizer"),
  tree: document.getElementById("tree"),
  content: document.getElementById("content"),
  treemapFrame: document.getElementById("treemapFrame"),
  treemapTileCap: document.getElementById("treemapTileCap"),
  treemap: document.getElementById("treemap"),
  homeResizer: document.getElementById("homeResizer"),
  topFiles: document.getElementById("topFiles"),
  topFilesTitle: document.getElementById("topFilesTitle"),
  topFilesLimit: document.getElementById("topFilesLimit"),
  topFilesBody: document.getElementById("topFilesBody"),
  details: document.getElementById("details"),
  detailName: document.getElementById("detailName"),
  detailPath: document.getElementById("detailPath"),
  detailStats: document.getElementById("detailStats"),
  tooltip: document.getElementById("tooltip")
};

function normalizeSearchText(value) {
  return String(value || "").trim().toLowerCase();
}

function searchTrigrams(value) {
  const text = normalizeSearchText(value);
  if (text.length < SEARCH_TRIGRAM_SIZE) return [];
  const seen = new Set();
  for (let index = 0; index <= text.length - SEARCH_TRIGRAM_SIZE; index++) {
    seen.add(text.slice(index, index + SEARCH_TRIGRAM_SIZE));
  }
  return Array.from(seen);
}

function addSearchCandidateIndexEntry(searchText, entryIndex) {
  searchTrigrams(searchText).forEach(trigram => {
    let entries = searchCandidateIndex.get(trigram);
    if (!entries) {
      entries = [];
      searchCandidateIndex.set(trigram, entries);
    }
    entries.push(entryIndex);
  });
}

function addSearchIndexEntry(node) {
  const name = node.name || "";
  const path = node.path || name;
  const ext = node.ext || "";
  const entry = {
    node,
    nameLower: normalizeSearchText(name),
    pathLower: normalizeSearchText(path),
    searchText: normalizeSearchText(`${name}\n${path}\n${ext}`)
  };
  const entryIndex = searchIndex.length;
  searchIndex.push(entry);
  addSearchCandidateIndexEntry(entry.searchText, entryIndex);
}

function walk(node, parentNode, depth = 0) {
  node.id = nextNodeId++;
  node.depth = depth;
  byId.set(node.id, node);
  byPath.set(node.path || node.name, node);
  parent.set(node.id, parentNode);
  addSearchIndexEntry(node);
  let total = 1;
  let files = node.type === "dir" ? 0 : 1;
  if (node.children) {
    node.children.forEach(child => {
      const counts = walk(child, node, depth + 1);
      total += counts.total;
      files += counts.files;
    });
  }
  node.items = total - 1;
  node.files = files;
  return { total, files };
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = value >= 100 || unit === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

function formatCount(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function dateFromModifiedValue(value) {
  if (value === undefined || value === null || value === "") return "";
  const text = String(value).trim();
  let date;
  if (/^-?\d+(\.\d+)?$/.test(text)) {
    const numeric = Number(text);
    const millis = Math.abs(numeric) < 100000000000 ? numeric * 1000 : numeric;
    date = new Date(millis);
  } else {
    date = new Date(text);
  }
  return !date || Number.isNaN(date.getTime()) ? "" : date;
}

function formatModifiedTime(value) {
  const date = dateFromModifiedValue(value);
  if (!date) return value === undefined || value === null || value === "" ? "" : String(value);
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(date);
}

function formatListModifiedTime(value) {
  const date = dateFromModifiedValue(value);
  if (!date) return value === undefined || value === null || value === "" ? "-" : String(value);
  return new Intl.DateTimeFormat(undefined, {
    year: "2-digit",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function modifiedSortValue(node) {
  const date = dateFromModifiedValue(node.mtime);
  return date ? date.getTime() : null;
}

function pct(part, total) {
  if (!total) return "0%";
  const value = part / total * 100;
  return value >= 10 ? `${value.toFixed(1)}%` : `${value.toFixed(2)}%`;
}

function hashString(value) {
  let hash = 0;
  for (let i = 0; i < value.length; i++) hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
  return Math.abs(hash);
}

function colorFor(node) {
  const key = node.type === "dir" ? "directory" : (node.ext || "[no extension]");
  const hash = hashString(key);
  return palette[Math.abs(hash) % palette.length];
}

function treemapColorFor(node) {
  if (node.ext === "[other]") return TREEMAP_SMALLER_ENTRIES_COLOR;
  if (node.type !== "dir") return colorFor(node);
  const hash = hashString(pathForNode(node) || node.name || String(node.id));
  const hue = 176 + (hash % 26);
  const saturation = 52 + (Math.floor(hash / 29) % 18);
  const lightness = 28 + (Math.floor(hash / 521) % 24);
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
}

function pathForNode(node) {
  return node.path || node.name || "";
}

function hashForNode(node) {
  return node === DATA ? "" : `#path=${encodeURIComponent(pathForNode(node))}`;
}

function currentUrlWithoutHash() {
  if (!window.location || !window.location.href) return "";
  const hashIndex = window.location.href.indexOf("#");
  return hashIndex >= 0 ? window.location.href.slice(0, hashIndex) : window.location.href;
}

function nodeFromLocationHash() {
  if (!window.location || !window.location.hash) return DATA;
  const hash = window.location.hash.slice(1);
  if (!hash) return DATA;

  let path = "";
  if (hash.startsWith("path=")) {
    path = hash.slice(5);
  } else {
    path = hash;
  }

  try {
    path = decodeURIComponent(path);
  } catch (error) {
    return null;
  }

  const node = byPath.get(path);
  return node && node.type === "dir" ? node : null;
}

function syncUrlToCurrent(node, replace = false) {
  if (!window.location) return;
  const base = currentUrlWithoutHash();
  if (!base) return;

  const nextUrl = base + hashForNode(node);
  if (window.location.href === nextUrl) return;

  const method = replace ? "replaceState" : "pushState";
  if (window.history && typeof window.history[method] === "function") {
    window.history[method](null, "", nextUrl);
  } else {
    window.location.hash = hashForNode(node);
  }
}

function applyLocationHash() {
  if (!DATA) return;
  const node = nodeFromLocationHash();
  if (!node || node === state.current) return;
  setCurrent(node, false);
}

function setCurrent(node, updateUrl = true) {
  if (!node) return;
  state.current = node;
  state.selected = node;
  if (updateUrl) syncUrlToCurrent(node);
  renderSafely();
}

function goParent() {
  if (!state.current) return;
  const parentNode = parent.get(state.current.id);
  if (parentNode) setCurrent(parentNode);
}

function directoryForNode(node) {
  let cursor = node && node.type === "dir" ? node : parent.get(node.id);
  while (cursor && cursor.type !== "dir") {
    cursor = parent.get(cursor.id);
  }
  return cursor || DATA;
}

function setSelected(node) {
  if (!node) return;
  state.selected = node;
  renderDetails();
  document.querySelectorAll(".row.active, .tile.active, .top-file-row.active").forEach(item => item.classList.remove("active"));
  document.querySelectorAll(`[data-id="${node.id}"]`).forEach(item => item.classList.add("active"));
}

function searchEntryMatches(entry, terms) {
  for (let index = 0; index < terms.length; index++) {
    if (!entry.searchText.includes(terms[index])) return false;
  }
  return true;
}

function searchScore(entry, terms, query) {
  const node = entry.node;
  let score = node.type === "dir" ? 0 : 6;
  if (entry.nameLower === query) {
    score -= 80;
  } else if (entry.nameLower.startsWith(query)) {
    score -= 60;
  } else if (entry.pathLower.endsWith(`/${query}`)) {
    score -= 45;
  } else if (entry.nameLower.includes(query)) {
    score -= 30;
  }

  terms.forEach(term => {
    const nameIndex = entry.nameLower.indexOf(term);
    if (nameIndex === 0) {
      score -= 10;
    } else if (nameIndex > 0) {
      score += nameIndex / 24;
    } else {
      const pathIndex = entry.pathLower.indexOf(term);
      score += pathIndex >= 0 ? 12 + pathIndex / 80 : 40;
    }
  });
  score += Math.min(16, node.depth || 0);
  score -= Math.min(18, Math.log2((node.size || 0) + 1));
  return score;
}

function insertSearchResult(results, candidate, limit) {
  if (results.length >= limit && candidate.score >= results[results.length - 1].score) return;
  let index = results.length;
  while (index > 0 && candidate.score < results[index - 1].score) index--;
  results.splice(index, 0, candidate);
  if (results.length > limit) results.pop();
}

function candidateIndexesForSearchTerms(terms) {
  let bestCandidates = null;
  for (let termIndex = 0; termIndex < terms.length; termIndex++) {
    const term = terms[termIndex];
    if (term.length < SEARCH_TRIGRAM_SIZE) continue;
    const trigrams = searchTrigrams(term);
    for (let trigramIndex = 0; trigramIndex < trigrams.length; trigramIndex++) {
      const candidates = searchCandidateIndex.get(trigrams[trigramIndex]);
      if (!candidates) return [];
      if (!bestCandidates || candidates.length < bestCandidates.length) bestCandidates = candidates;
    }
  }
  return bestCandidates;
}

function findSearchMatches(query, limit = SEARCH_RESULT_LIMIT) {
  const normalized = normalizeSearchText(query);
  if (!normalized) return [];
  const terms = normalized.split(/\s+/).filter(Boolean);
  if (!terms.length) return [];

  const results = [];
  const candidateIndexes = candidateIndexesForSearchTerms(terms);
  const fullScan = candidateIndexes === null;
  const candidateCount = fullScan ? searchIndex.length : candidateIndexes.length;
  for (let index = 0; index < candidateCount; index++) {
    const entry = fullScan ? searchIndex[index] : searchIndex[candidateIndexes[index]];
    if (!searchEntryMatches(entry, terms)) continue;
    insertSearchResult(results, {
      node: entry.node,
      score: searchScore(entry, terms, normalized)
    }, limit);
  }
  return results;
}

function closeSearchResults() {
  if (searchTimer) {
    clearTimeout(searchTimer);
    searchTimer = 0;
  }
  searchResults = [];
  state.searchActiveIndex = -1;
  el.searchResults.textContent = "";
  el.searchResults.hidden = true;
  el.searchInput.setAttribute("aria-expanded", "false");
}

function updateSearchActiveResult() {
  el.searchResults.querySelectorAll(".search-result").forEach((row, index) => {
    const active = index === state.searchActiveIndex;
    row.classList.toggle("active", active);
    row.setAttribute("aria-selected", active ? "true" : "false");
    if (active) row.scrollIntoView({ block: "nearest" });
  });
}

function renderSearchResultsForQuery(query) {
  const normalized = normalizeSearchText(query);
  el.searchResults.textContent = "";
  if (!normalized) {
    closeSearchResults();
    return;
  }

  searchResults = findSearchMatches(normalized);
  el.searchResults.hidden = false;
  el.searchInput.setAttribute("aria-expanded", "true");
  if (!searchResults.length) {
    state.searchActiveIndex = -1;
    const empty = document.createElement("div");
    empty.className = "search-empty";
    empty.textContent = "No matches";
    el.searchResults.appendChild(empty);
    return;
  }

  state.searchActiveIndex = 0;
  const fragment = document.createDocumentFragment();
  searchResults.forEach((match, index) => {
    const node = match.node;
    const row = document.createElement("button");
    row.type = "button";
    row.className = "search-result";
    row.setAttribute("role", "option");
    row.setAttribute("aria-selected", index === state.searchActiveIndex ? "true" : "false");
    row.addEventListener("mousedown", event => event.preventDefault());
    row.addEventListener("click", () => activateSearchResult(index));

    const main = document.createElement("div");
    const name = document.createElement("div");
    name.className = "search-result-name";
    name.textContent = node.name || pathForNode(node);
    const path = document.createElement("div");
    path.className = "search-result-path";
    path.textContent = pathForNode(node);
    main.append(name, path);

    const meta = document.createElement("div");
    meta.className = "search-result-meta";
    meta.textContent = `${node.type.toUpperCase()} · ${formatBytes(node.size)}`;
    row.append(main, meta);
    fragment.appendChild(row);
  });
  el.searchResults.appendChild(fragment);
  updateSearchActiveResult();
}

function scheduleSearchResults() {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchTimer = 0;
    renderSearchResultsForQuery(el.searchInput.value);
  }, SEARCH_DEBOUNCE_MS);
}

function activateSearchResult(index = state.searchActiveIndex) {
  const match = searchResults[index] || searchResults[0];
  if (!match) return;
  const node = match.node;
  closeSearchResults();
  el.searchInput.blur();
  const targetDirectory = node.type === "dir" ? node : directoryForNode(node);
  setCurrent(targetDirectory);
  if (node.id !== targetDirectory.id) {
    setSelected(node);
    scrollTreeSelectionIntoView(node);
  }
}

function moveSearchActiveResult(delta) {
  if (!searchResults.length) return;
  state.searchActiveIndex = (state.searchActiveIndex + delta + searchResults.length) % searchResults.length;
  updateSearchActiveResult();
}

function focusSearch() {
  if (!DATA) return;
  el.searchInput.focus();
  el.searchInput.select();
  renderSearchResultsForQuery(el.searchInput.value);
}

function selectSearchInputText() {
  if (el.searchInput.value) el.searchInput.select();
}

function ensureListSelection(children) {
  if (!children.length) {
    state.selected = state.current;
    return;
  }
  if (!state.selected || state.selected === state.current || !children.some(child => child.id === state.selected.id)) {
    state.selected = children[0];
  }
}

function pathToRoot(node) {
  const items = [];
  let cursor = node;
  while (cursor) {
    items.unshift(cursor);
    cursor = parent.get(cursor.id);
  }
  return items;
}

function makeHomeIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("viewBox", "0 0 24 24");
  [
    "M3 10.5 12 3l9 7.5",
    "M5 10v10h14V10",
    "M9 20v-6h6v6"
  ].forEach(d => {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
  });
  return svg;
}

function makeUpIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("viewBox", "0 0 24 24");
  [
    "M12 19V5",
    "m5 12 7-7 7 7"
  ].forEach(d => {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
  });
  return svg;
}

function makeColumnsIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("viewBox", "0 0 24 24");
  [
    "M4 5h16",
    "M4 12h16",
    "M4 19h16",
    "M8 5v14",
    "M16 5v14"
  ].forEach(d => {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
  });
  return svg;
}

function renderCrumbs() {
  el.crumbs.textContent = "";
  pathToRoot(state.current).forEach((node, index, nodes) => {
    const button = document.createElement("button");
    button.className = index === 0 ? "crumb root" : "crumb";
    if (index === 0) {
      button.appendChild(makeHomeIcon());
    } else {
      button.textContent = node.name;
    }
    button.title = node.path || node.name;
    button.setAttribute("aria-label", index === 0 ? "Root" : node.name);
    button.addEventListener("click", () => setCurrent(node));
    el.crumbs.appendChild(button);
    if (index < nodes.length - 1) {
      const sep = document.createElement("span");
      sep.className = "sep";
      sep.textContent = "/";
      el.crumbs.appendChild(sep);
    }
  });
}

function filteredChildren(node) {
  return (node.children || []).slice();
}

function sortedChildren(node) {
  const children = filteredChildren(node);
  const direction = state.sortDir === "asc" ? 1 : -1;
  children.sort((a, b) => {
    let result = 0;
    if (state.sortKey === "name") {
      result = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
    } else if (state.sortKey === "items") {
      result = (a.items || 0) - (b.items || 0);
    } else if (state.sortKey === "files") {
      result = (a.files || 0) - (b.files || 0);
    } else if (state.sortKey === "modified") {
      const aTime = modifiedSortValue(a);
      const bTime = modifiedSortValue(b);
      if (aTime === null && bTime === null) {
        result = 0;
      } else if (aTime === null) {
        return 1;
      } else if (bTime === null) {
        return -1;
      } else {
        result = aTime - bTime;
      }
    } else {
      result = (a.size || 0) - (b.size || 0);
    }
    if (result !== 0) return result * direction;
    result = (b.size || 0) - (a.size || 0);
    if (result !== 0) return result;
    return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
  });
  return children;
}

function sortIndicator(key) {
  if (state.sortKey !== key) return "";
  return state.sortDir === "asc" ? " ↑" : " ↓";
}

function setSort(key) {
  if (state.sortKey === key) {
    state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
  } else {
    state.sortKey = key;
    state.sortDir = key === "name" ? "asc" : "desc";
  }
  renderTree();
  setSelected(state.selected);
}

function handleSortShortcut(event) {
  if (event.altKey || event.ctrlKey || event.metaKey) return false;
  const key = SORT_SHORTCUTS.get(event.key);
  if (!key) return false;
  event.preventDefault();
  setSort(key);
  return true;
}

function currentTreeChildren() {
  if (treeView.node === state.current) return treeView.children;
  return sortedChildren(state.current);
}

function defaultTreeColumns() {
  return { ...DEFAULT_TREE_COLUMNS };
}

function readStoredTreeColumns() {
  const columns = defaultTreeColumns();
  try {
    const stored = JSON.parse(localStorage.getItem(TREE_COLUMN_STORAGE_KEY) || "{}");
    Object.keys(columns).forEach(key => {
      if (typeof stored[key] === "boolean") columns[key] = stored[key];
    });
  } catch (error) {
    // Column settings are optional; the report still works when storage is unavailable.
  }
  return columns;
}

function storeTreeColumns() {
  try {
    localStorage.setItem(TREE_COLUMN_STORAGE_KEY, JSON.stringify(state.visibleColumns));
  } catch (error) {
    // Ignore storage failures in strict file contexts.
  }
}

function isTreeColumnVisible(key) {
  if (key === "name") return true;
  return state.visibleColumns[key] !== false;
}

function visibleTreeColumns() {
  return TREE_COLUMNS.filter(column => isTreeColumnVisible(column.key));
}

function applyTreeColumnLayout() {
  const columns = visibleTreeColumns();
  const template = columns.map(column => column.grid).join(" ");
  const minWidth = columns.reduce((total, column) => total + column.minWidth, 0) +
    Math.max(0, columns.length - 1) * 8 +
    22;
  el.tree.style.setProperty("--tree-columns", template);
  el.tree.style.setProperty("--tree-min-width", `${Math.max(300, minWidth)}px`);
}

function closeTreeColumnsMenu(focusButton = false) {
  const menu = el.tree.querySelector(".tree-columns-menu");
  const button = el.tree.querySelector(".tree-columns-btn");
  if (!menu || menu.hidden) return false;
  menu.hidden = true;
  if (button) {
    button.setAttribute("aria-expanded", "false");
    if (focusButton) button.focus();
  }
  return true;
}

function reopenTreeColumnsMenu() {
  const menu = el.tree.querySelector(".tree-columns-menu");
  const button = el.tree.querySelector(".tree-columns-btn");
  if (!menu || !button) return;
  menu.hidden = false;
  button.setAttribute("aria-expanded", "true");
}

function setTreeColumnVisible(key, visible) {
  state.visibleColumns[key] = visible;
  storeTreeColumns();
  renderTree();
  setSelected(state.selected);
  reopenTreeColumnsMenu();
}

function makeTreeColumnsButton(menu) {
  const button = document.createElement("button");
  button.className = "tree-columns-btn";
  button.type = "button";
  button.title = "Column settings";
  button.setAttribute("aria-label", "Column settings");
  button.setAttribute("aria-haspopup", "true");
  button.setAttribute("aria-expanded", "false");
  button.appendChild(makeColumnsIcon());
  button.addEventListener("click", event => {
    event.stopPropagation();
    const open = menu.hidden;
    closeTreeColumnsMenu();
    menu.hidden = !open;
    button.setAttribute("aria-expanded", String(open));
  });
  return button;
}

function makeTreeColumnsMenu() {
  const menu = document.createElement("div");
  menu.className = "tree-columns-menu";
  menu.hidden = true;
  menu.addEventListener("click", event => event.stopPropagation());

  const title = document.createElement("div");
  title.className = "tree-columns-title";
  title.textContent = "Columns";
  menu.appendChild(title);

  TREE_COLUMNS.filter(column => !column.required).forEach(column => {
    const label = document.createElement("label");
    label.className = "tree-column-option";

    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = isTreeColumnVisible(column.key);
    input.addEventListener("change", () => setTreeColumnVisible(column.key, input.checked));

    const text = document.createElement("span");
    text.textContent = column.menuLabel;
    label.append(input, text);
    menu.appendChild(label);
  });
  return menu;
}

function makeHeaderButton(label, key, numeric = key !== "name" && key !== "modified") {
  const button = document.createElement("button");
  button.className = "tree-sort";
  if (numeric) button.classList.add("numeric");
  if (state.sortKey === key) button.classList.add("sort-active");
  button.type = "button";
  button.textContent = label + sortIndicator(key);
  button.title = `Sort by ${label.toLowerCase()}`;
  button.addEventListener("click", () => setSort(key));
  return button;
}

function makeParentHeaderButton() {
  const button = document.createElement("button");
  const parentNode = parent.get(state.current.id);
  button.className = "tree-parent-btn";
  button.type = "button";
  button.title = parentNode ? "Parent" : "Already at root";
  button.setAttribute("aria-label", "Parent");
  button.disabled = !parentNode;
  button.appendChild(makeUpIcon());
  button.addEventListener("click", goParent);
  return button;
}

function makeHeaderLabel(label, numeric = false) {
  const span = document.createElement("span");
  span.className = numeric ? "tree-label numeric" : "tree-label";
  span.textContent = label;
  return span;
}

function renderTreeHeader() {
  const header = document.createElement("div");
  header.className = "tree-header";
  const columnsMenu = makeTreeColumnsMenu();
  const nameHead = document.createElement("div");
  nameHead.className = "tree-name-head";
  nameHead.append(makeParentHeaderButton(), makeHeaderButton("Name", "name"), makeTreeColumnsButton(columnsMenu));

  const cells = visibleTreeColumns().map(column => {
    if (column.key === "name") return nameHead;
    if (column.sortKey) return makeHeaderButton(column.label, column.sortKey, column.numeric);
    return makeHeaderLabel(column.label, column.numeric);
  });
  header.append(...cells, columnsMenu);
  el.tree.appendChild(header);
}

function resetTreeView() {
  treeView.node = null;
  treeView.children = [];
  treeView.total = 0;
  treeView.body = null;
  treeView.start = -1;
  treeView.end = -1;
}

function createTreeRow(child, total) {
  const row = document.createElement("div");
  row.className = `row ${child.type}`;
  if (state.selected && child.id === state.selected.id) row.classList.add("active");
  row.dataset.id = child.id;
  row.style.setProperty("--bar", `${Math.max(2, child.size / Math.max(total, 1) * 100)}%`);
  row.style.setProperty("--row-color", colorFor(child));
  row.title = child.path || child.name;
  row.addEventListener("click", () => setSelected(child));
  row.addEventListener("dblclick", () => {
    if (child.type === "dir") setCurrent(child);
  });

  const name = document.createElement("div");
  name.className = "row-name";
  const swatch = document.createElement("span");
  swatch.className = "swatch";
  const kind = document.createElement("span");
  kind.className = "row-kind";
  kind.textContent = child.type === "dir" ? "DIR" : "FILE";
  const label = document.createElement("span");
  label.textContent = child.name;
  name.append(swatch, kind, label);

  const size = document.createElement("div");
  size.className = "row-size";
  size.textContent = formatBytes(child.size);

  const items = document.createElement("div");
  items.className = "row-count";
  items.textContent = formatCount(child.items);

  const files = document.createElement("div");
  files.className = "row-count";
  files.textContent = formatCount(child.files);

  const modified = document.createElement("div");
  modified.className = "row-modified";
  modified.textContent = formatListModifiedTime(child.mtime);
  modified.title = formatModifiedTime(child.mtime) || "Modified time unavailable";

  const percent = document.createElement("div");
  percent.className = "row-pct";
  percent.textContent = pct(child.size, total);

  const cells = [name];
  if (isTreeColumnVisible("items")) cells.push(items);
  if (isTreeColumnVisible("files")) cells.push(files);
  if (isTreeColumnVisible("size")) cells.push(size);
  if (isTreeColumnVisible("modified")) cells.push(modified);
  if (isTreeColumnVisible("percent")) cells.push(percent);
  row.append(...cells);
  return row;
}

function renderVisibleTreeRows(force = false) {
  if (!treeView.body) return;
  const header = el.tree.querySelector(".tree-header");
  const headerHeight = header ? header.offsetHeight : 0;
  const bodyScrollTop = Math.max(0, el.tree.scrollTop - headerHeight);
  const viewportHeight = Math.max(0, el.tree.clientHeight - headerHeight);
  const start = Math.max(0, Math.floor(bodyScrollTop / TREE_ROW_HEIGHT) - TREE_OVERSCAN_ROWS);
  const end = Math.min(
    treeView.children.length,
    Math.ceil((bodyScrollTop + viewportHeight) / TREE_ROW_HEIGHT) + TREE_OVERSCAN_ROWS
  );
  if (!force && start === treeView.start && end === treeView.end) return;

  treeView.start = start;
  treeView.end = end;
  treeView.body.textContent = "";
  const fragment = document.createDocumentFragment();
  for (let index = start; index < end; index++) {
    const row = createTreeRow(treeView.children[index], treeView.total);
    row.style.transform = `translateY(${index * TREE_ROW_HEIGHT}px)`;
    fragment.appendChild(row);
  }
  treeView.body.appendChild(fragment);
}

function renderTree() {
  el.tree.textContent = "";
  resetTreeView();
  applyTreeColumnLayout();
  renderTreeHeader();
  const children = sortedChildren(state.current);
  ensureListSelection(children);
  const total = state.current.size || children.reduce((sum, child) => sum + child.size, 0);
  if (!children.length) {
    const empty = document.createElement("div");
    empty.className = "row";
    empty.textContent = "No entries";
    el.tree.appendChild(empty);
    return;
  }

  const body = document.createElement("div");
  body.className = "tree-body";
  body.style.height = `${children.length * TREE_ROW_HEIGHT}px`;
  el.tree.appendChild(body);
  treeView.node = state.current;
  treeView.children = children;
  treeView.total = total;
  treeView.body = body;
  renderVisibleTreeRows(true);
}

function effectiveTreemapVisibleEntryLimit(maxItems = DEFAULT_TREEMAP_TILE_CAP) {
  const numeric = Number(maxItems);
  const requestedLimit = Number.isFinite(numeric) ? Math.max(0, Math.floor(numeric)) : DEFAULT_TREEMAP_TILE_CAP;
  return requestedLimit;
}

function treemapItems(node, maxItems = DEFAULT_TREEMAP_TILE_CAP) {
  const entryLimit = effectiveTreemapVisibleEntryLimit(maxItems);
  if (entryLimit <= 0) return [];
  const entries = (node.children || [])
    .filter(child => child.size > 0)
    .sort((a, b) => b.size - a.size);
  if (!entries.length && node.type !== "dir" && node.size > 0) return [node];
  if (entries.length <= entryLimit) return entries;

  const visible = entries.slice(0, entryLimit);
  const hidden = entries.slice(entryLimit);
  const hiddenSize = hidden.reduce((sum, item) => sum + item.size, 0);
  if (hiddenSize > 0) {
    visible.push({
      id: `other-${node.id}`,
      name: `${formatCount(hidden.length)} smaller ${hidden.length === 1 ? "entry" : "entries"}`,
      path: `${node.path || node.name} / smaller entries`,
      size: hiddenSize,
      type: "file",
      ext: "[other]",
      children: [],
      items: hidden.reduce((sum, item) => sum + (item.items || 0) + 1, 0),
      files: hidden.reduce((sum, item) => sum + (item.files || (item.type === "file" ? 1 : 0)), 0),
      depth: (node.depth || 0) + 1
    });
  }
  return visible;
}

function hasTreemapChildren(node) {
  return node.type === "dir" && (node.children || []).some(child => child.size > 0);
}

function nestedTreemapBounds(node, rect, depth) {
  if (!hasTreemapChildren(node) || depth >= TREEMAP_MAX_DEPTH) return null;
  if (rect.w < TREEMAP_MIN_NESTED_WIDTH || rect.h < TREEMAP_MIN_NESTED_HEIGHT) return null;

  const labelHeight = rect.w > 56 && rect.h > 32 ? TREEMAP_CHILD_LABEL_HEIGHT : TREEMAP_CHILD_INSET;
  const x = TREEMAP_CHILD_INSET;
  const y = labelHeight;
  const w = rect.w - TREEMAP_CHILD_INSET * 2;
  const h = rect.h - y - TREEMAP_CHILD_INSET;
  if (w < 24 || h < 24) return null;
  return { x, y, w, h };
}

function layoutTreemap(items, x, y, w, h) {
  const total = items.reduce((sum, item) => sum + item.size, 0);
  if (!total || !items.length || w <= 0 || h <= 0) return [];

  const rects = [];
  let row = [];
  let rowSize = 0;
  let remaining = items.slice();
  let offsetX = x;
  let offsetY = y;
  let width = w;
  let height = h;

  while (remaining.length) {
    const item = remaining[0];
    const nextRow = row.concat(item);
    const nextSize = rowSize + item.size;
    const side = Math.min(width, height);
    if (!row.length || worst(nextRow, nextSize, side) <= worst(row, rowSize, side)) {
      row = nextRow;
      rowSize = nextSize;
      remaining.shift();
    } else {
      placeRow(row, rowSize);
      row = [];
      rowSize = 0;
    }
  }
  if (row.length) placeRow(row, rowSize);
  return rects;

  function worst(rowItems, size, side) {
    if (!size || !side || !rowItems.length) return Infinity;
    let max = 0;
    let min = Infinity;
    rowItems.forEach(item => {
      const area = item.size / total * w * h;
      if (area > max) max = area;
      if (area < min) min = area;
    });
    if (!min || !Number.isFinite(min)) return Infinity;
    const side2 = side * side;
    const rowArea = sizeArea(size);
    return Math.max(side2 * max / (rowArea * rowArea), rowArea * rowArea / (side2 * min));
  }

  function sizeArea(size) {
    return size / total * w * h;
  }

  function placeRow(rowItems, size) {
    const area = sizeArea(size);
    if (width >= height) {
      const rowHeight = area / width;
      let cx = offsetX;
      rowItems.forEach(item => {
        const itemWidth = sizeArea(item.size) / rowHeight;
        rects.push({ node: item, x: cx, y: offsetY, w: itemWidth, h: rowHeight });
        cx += itemWidth;
      });
      offsetY += rowHeight;
      height -= rowHeight;
    } else {
      const rowWidth = area / height;
      let cy = offsetY;
      rowItems.forEach(item => {
        const itemHeight = sizeArea(item.size) / rowWidth;
        rects.push({ node: item, x: offsetX, y: cy, w: rowWidth, h: itemHeight });
        cy += itemHeight;
      });
      offsetX += rowWidth;
      width -= rowWidth;
    }
  }
}

function topLevelDirectoryTileRect(rect, node, depth) {
  if (depth !== 0 || node.type !== "dir") return rect;
  const gap = Math.min(TREEMAP_TOP_LEVEL_DIR_GAP, Math.max(0, (Math.min(rect.w, rect.h) - 2) / 2));
  return {
    ...rect,
    x: rect.x + gap,
    y: rect.y + gap,
    w: Math.max(0, rect.w - gap * 2),
    h: Math.max(0, rect.h - gap * 2)
  };
}

function renderTreemapTile(container, rect, depth, maxItems) {
  if (rect.w < 1 || rect.h < 1) return;
  const node = rect.node;
  const tileRect = topLevelDirectoryTileRect(rect, node, depth);
  if (tileRect.w < 1 || tileRect.h < 1) return;
  const childBounds = nestedTreemapBounds(node, tileRect, depth);
  const childItems = childBounds ? treemapItems(node, maxItems) : [];
  const childRects = childItems.length
    ? layoutTreemap(childItems, 0, 0, childBounds.w, childBounds.h)
    : [];
  const hasNestedTiles = childRects.length > 0;
  const tile = document.createElement("div");
  tile.className = `tile ${node.type}${depth > 0 ? " nested" : ""}${depth === 0 && node.type === "dir" ? " top-level-dir" : ""}${hasNestedTiles ? " has-children" : ""}`;
  tile.dataset.id = node.id;
  tile.style.left = `${tileRect.x}px`;
  tile.style.top = `${tileRect.y}px`;
  tile.style.width = `${Math.max(0, tileRect.w)}px`;
  tile.style.height = `${Math.max(0, tileRect.h)}px`;
  tile.style.setProperty("--tile-color", treemapColorFor(node));
  tile.title = "";
  tile.addEventListener("click", event => {
    event.stopPropagation();
    setSelected(node);
  });
  tile.addEventListener("dblclick", event => {
    event.stopPropagation();
    if (node.type === "dir") setCurrent(node);
  });
  tile.addEventListener("mousemove", event => {
    event.stopPropagation();
    showTooltip(event, node);
  });
  tile.addEventListener("mouseleave", hideTooltip);
  if (node.type === "dir" && tileRect.w > 52 && tileRect.h > 28) {
    const kind = document.createElement("div");
    kind.className = "tile-kind";
    kind.textContent = "DIR";
    tile.appendChild(kind);
  }
  if (tileRect.w > 56 && tileRect.h > 32) {
    const label = document.createElement("div");
    label.className = "tile-label";
    label.textContent = node.name;
    tile.appendChild(label);
  }

  if (hasNestedTiles) {
    const childLayer = document.createElement("div");
    childLayer.className = "tile-children";
    childLayer.style.left = `${childBounds.x}px`;
    childLayer.style.top = `${childBounds.y}px`;
    childLayer.style.width = `${childBounds.w}px`;
    childLayer.style.height = `${childBounds.h}px`;
    childRects.forEach(childRect => renderTreemapTile(childLayer, childRect, depth + 1, maxItems));
    if (childLayer.childElementCount) tile.appendChild(childLayer);
  }

  container.appendChild(tile);
}

function renderTreemap() {
  el.treemap.textContent = "";
  const bounds = el.treemap.getBoundingClientRect();
  state.treemapTileCap = normalizeTreemapTileCap(state.treemapTileCap);
  el.treemapTileCap.value = String(state.treemapTileCap);
  const entryLimit = effectiveTreemapVisibleEntryLimit(state.treemapTileCap);
  el.treemap.setAttribute("aria-label", `Treemap, showing up to ${entryLimit} entries per directory before grouping smaller entries`);
  const items = treemapItems(state.current, entryLimit);
  const rects = layoutTreemap(items, 0, 0, bounds.width, bounds.height);
  if (!rects.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Empty";
    el.treemap.appendChild(empty);
    return;
  }

  rects.forEach(rect => {
    renderTreemapTile(el.treemap, rect, 0, entryLimit);
  });
}

function collectFiles(node, files) {
  if (node.type !== "dir") {
    if (node.size > 0) files.push(node);
    return;
  }
  (node.children || []).forEach(child => collectFiles(child, files));
}

function normalizeTopFilesLimit(value) {
  const numeric = Number(value);
  return TOP_FILES_LIMITS.includes(numeric) ? numeric : TOP_FILES_LIMITS[0];
}

function normalizeTreemapTileCap(value) {
  const numeric = Number(value);
  return TREEMAP_TILE_CAP_OPTIONS.includes(numeric) ? numeric : DEFAULT_TREEMAP_TILE_CAP;
}

function readStoredTreemapTileCap() {
  try {
    return normalizeTreemapTileCap(localStorage.getItem(TREEMAP_TILE_CAP_STORAGE_KEY));
  } catch (error) {
    return DEFAULT_TREEMAP_TILE_CAP;
  }
}

function storeTreemapTileCap(value) {
  try {
    localStorage.setItem(TREEMAP_TILE_CAP_STORAGE_KEY, String(value));
  } catch (error) {
    // The report still works when localStorage is unavailable.
  }
}

function isMainResizerVisible() {
  return getComputedStyle(el.mainResizer).display !== "none";
}

function readStoredMainSidebarSize() {
  try {
    const value = Number(localStorage.getItem(MAIN_PANE_STORAGE_KEY));
    return Number.isFinite(value) && value > 0 ? value : 0;
  } catch (error) {
    return 0;
  }
}

function storeMainSidebarSize(size) {
  try {
    localStorage.setItem(MAIN_PANE_STORAGE_KEY, String(Math.round(size)));
  } catch (error) {
    // The report still works when localStorage is unavailable.
  }
}

function mainSidebarMaxSize() {
  const width = el.main.getBoundingClientRect().width;
  return Math.max(MAIN_MIN_SIDEBAR_SIZE, width - MAIN_MIN_CONTENT_SIZE - MAIN_RESIZER_SIZE);
}

function clampMainSidebarSize(size) {
  return Math.max(MAIN_MIN_SIDEBAR_SIZE, Math.min(mainSidebarMaxSize(), size || MAIN_MIN_SIDEBAR_SIZE));
}

function currentMainSidebarSize() {
  const inlineSize = parseFloat(el.main.style.getPropertyValue("--sidebar-size"));
  if (Number.isFinite(inlineSize)) return inlineSize;

  const sidebarRect = el.sidebar.getBoundingClientRect();
  return sidebarRect.width || MAIN_MIN_SIDEBAR_SIZE;
}

function updateMainResizerAttributes(size = currentMainSidebarSize()) {
  const clamped = clampMainSidebarSize(size);
  el.mainResizer.setAttribute("aria-valuemin", String(MAIN_MIN_SIDEBAR_SIZE));
  el.mainResizer.setAttribute("aria-valuemax", String(Math.round(mainSidebarMaxSize())));
  el.mainResizer.setAttribute("aria-valuenow", String(Math.round(clamped)));
}

function setMainSidebarSize(size, persist = true, rerender = true) {
  if (!isMainResizerVisible()) return;
  const clamped = clampMainSidebarSize(size);
  el.main.style.setProperty("--sidebar-size", `${Math.round(clamped)}px`);
  updateMainResizerAttributes(clamped);
  if (persist) storeMainSidebarSize(clamped);
  if (rerender) renderTreemap();
}

function syncMainPaneSize() {
  if (!isMainResizerVisible()) return;
  const currentInlineSize = el.main.style.getPropertyValue("--sidebar-size");
  if (!currentInlineSize) {
    const stored = readStoredMainSidebarSize();
    if (stored) {
      setMainSidebarSize(stored, false, false);
      return;
    }
  } else {
    setMainSidebarSize(currentMainSidebarSize(), false, false);
    return;
  }
  updateMainResizerAttributes();
}

function resizeMainPaneAt(clientX) {
  const rect = el.main.getBoundingClientRect();
  setMainSidebarSize(clientX - rect.left);
}

function beginMainResize(event) {
  if (event.button !== undefined && event.button !== 0) return;
  event.preventDefault();
  hideTooltip();
  el.mainResizer.classList.add("dragging");
  document.body.classList.add("resizing-main-pane");
  resizeMainPaneAt(event.clientX);
  window.addEventListener("pointermove", handleMainResizeMove);
  window.addEventListener("pointerup", endMainResize);
  window.addEventListener("pointercancel", endMainResize);
}

function handleMainResizeMove(event) {
  event.preventDefault();
  resizeMainPaneAt(event.clientX);
}

function endMainResize() {
  window.removeEventListener("pointermove", handleMainResizeMove);
  window.removeEventListener("pointerup", endMainResize);
  window.removeEventListener("pointercancel", endMainResize);
  el.mainResizer.classList.remove("dragging");
  document.body.classList.remove("resizing-main-pane");
}

function handleMainResizerKey(event) {
  let handled = true;
  if (event.key === "ArrowLeft") {
    setMainSidebarSize(currentMainSidebarSize() - MAIN_RESIZE_STEP);
  } else if (event.key === "ArrowRight") {
    setMainSidebarSize(currentMainSidebarSize() + MAIN_RESIZE_STEP);
  } else if (event.key === "PageUp") {
    setMainSidebarSize(currentMainSidebarSize() - MAIN_RESIZE_STEP * 3);
  } else if (event.key === "PageDown") {
    setMainSidebarSize(currentMainSidebarSize() + MAIN_RESIZE_STEP * 3);
  } else if (event.key === "Home") {
    setMainSidebarSize(MAIN_MIN_SIDEBAR_SIZE);
  } else if (event.key === "End") {
    setMainSidebarSize(mainSidebarMaxSize());
  } else {
    handled = false;
  }

  if (handled) event.preventDefault();
}

function readStoredHomeTreemapSize() {
  try {
    const value = Number(localStorage.getItem(HOME_TREEMAP_STORAGE_KEY));
    return Number.isFinite(value) && value > 0 ? value : 0;
  } catch (error) {
    return 0;
  }
}

function storeHomeTreemapSize(size) {
  try {
    localStorage.setItem(HOME_TREEMAP_STORAGE_KEY, String(Math.round(size)));
  } catch (error) {
    // The report still works when localStorage is unavailable.
  }
}

function homeTreemapMaxSize() {
  const height = el.content.getBoundingClientRect().height;
  return Math.max(HOME_MIN_TREEMAP_SIZE, height - HOME_MIN_TOP_FILES_SIZE - HOME_RESIZER_SIZE);
}

function clampHomeTreemapSize(size) {
  return Math.max(HOME_MIN_TREEMAP_SIZE, Math.min(homeTreemapMaxSize(), size || HOME_MIN_TREEMAP_SIZE));
}

function currentHomeTreemapSize() {
  const inlineSize = parseFloat(el.content.style.getPropertyValue("--home-treemap-size"));
  if (Number.isFinite(inlineSize)) return inlineSize;

  const contentRect = el.content.getBoundingClientRect();
  const frameRect = el.treemapFrame.getBoundingClientRect();
  if (frameRect.height > 0) {
    const frameStyle = getComputedStyle(el.treemapFrame);
    const marginBottom = parseFloat(frameStyle.marginBottom) || 0;
    return frameRect.bottom - contentRect.top + marginBottom;
  }
  return HOME_MIN_TREEMAP_SIZE;
}

function updateHomeResizerAttributes(size = currentHomeTreemapSize()) {
  const clamped = clampHomeTreemapSize(size);
  el.homeResizer.setAttribute("aria-valuemin", String(HOME_MIN_TREEMAP_SIZE));
  el.homeResizer.setAttribute("aria-valuemax", String(Math.round(homeTreemapMaxSize())));
  el.homeResizer.setAttribute("aria-valuenow", String(Math.round(clamped)));
}

function setHomeTreemapSize(size, persist = true, rerender = true) {
  const clamped = clampHomeTreemapSize(size);
  el.content.style.setProperty("--home-treemap-size", `${Math.round(clamped)}px`);
  updateHomeResizerAttributes(clamped);
  if (persist) storeHomeTreemapSize(clamped);
  if (rerender) renderTreemap();
}

function syncHomePaneSize() {
  if (state.current !== DATA) return;
  const currentInlineSize = el.content.style.getPropertyValue("--home-treemap-size");
  if (!currentInlineSize) {
    const stored = readStoredHomeTreemapSize();
    if (stored) {
      setHomeTreemapSize(stored, false, false);
      return;
    }
  } else {
    setHomeTreemapSize(currentHomeTreemapSize(), false, false);
    return;
  }
  updateHomeResizerAttributes();
}

function resizeHomePaneAt(clientY) {
  const rect = el.content.getBoundingClientRect();
  setHomeTreemapSize(clientY - rect.top);
}

function beginHomeResize(event) {
  if (event.button !== undefined && event.button !== 0) return;
  event.preventDefault();
  hideTooltip();
  el.homeResizer.classList.add("dragging");
  document.body.classList.add("resizing-home-pane");
  resizeHomePaneAt(event.clientY);
  window.addEventListener("pointermove", handleHomeResizeMove);
  window.addEventListener("pointerup", endHomeResize);
  window.addEventListener("pointercancel", endHomeResize);
}

function handleHomeResizeMove(event) {
  event.preventDefault();
  resizeHomePaneAt(event.clientY);
}

function endHomeResize() {
  window.removeEventListener("pointermove", handleHomeResizeMove);
  window.removeEventListener("pointerup", endHomeResize);
  window.removeEventListener("pointercancel", endHomeResize);
  el.homeResizer.classList.remove("dragging");
  document.body.classList.remove("resizing-home-pane");
}

function handleHomeResizerKey(event) {
  let handled = true;
  if (event.key === "ArrowUp") {
    setHomeTreemapSize(currentHomeTreemapSize() - HOME_RESIZE_STEP);
  } else if (event.key === "ArrowDown") {
    setHomeTreemapSize(currentHomeTreemapSize() + HOME_RESIZE_STEP);
  } else if (event.key === "PageUp") {
    setHomeTreemapSize(currentHomeTreemapSize() - HOME_RESIZE_STEP * 3);
  } else if (event.key === "PageDown") {
    setHomeTreemapSize(currentHomeTreemapSize() + HOME_RESIZE_STEP * 3);
  } else if (event.key === "Home") {
    setHomeTreemapSize(HOME_MIN_TREEMAP_SIZE);
  } else if (event.key === "End") {
    setHomeTreemapSize(homeTreemapMaxSize());
  } else {
    handled = false;
  }

  if (handled) event.preventDefault();
}

function renderHomePanel() {
  const isHome = state.current === DATA;
  el.content.classList.toggle("home", isHome);
  el.homeResizer.hidden = !isHome;
  el.topFiles.hidden = !isHome;
  el.details.hidden = isHome;
  if (!isHome) {
    el.topFilesBody.textContent = "";
    return;
  }
  syncHomePaneSize();

  const files = [];
  collectFiles(DATA, files);
  files.sort((a, b) => b.size - a.size);
  state.topFilesLimit = normalizeTopFilesLimit(state.topFilesLimit);
  el.topFilesLimit.value = String(state.topFilesLimit);
  el.topFilesTitle.textContent = "List of biggest file";
  el.topFiles.setAttribute("aria-label", `List of biggest file, showing ${state.topFilesLimit} entries`);

  el.topFilesBody.textContent = "";
  el.topFilesBody.scrollTop = 0;
  if (!files.length) {
    const empty = document.createElement("div");
    empty.className = "top-file-row";
    empty.textContent = "No files";
    el.topFilesBody.appendChild(empty);
    return;
  }

  const topFiles = files.slice(0, state.topFilesLimit);
  topFiles.forEach(file => {
    const row = document.createElement("div");
    row.className = "top-file-row";
    row.dataset.id = file.id;
    row.title = file.path || file.name;
    row.addEventListener("click", () => setSelected(file));
    row.addEventListener("dblclick", () => setCurrent(directoryForNode(file)));

    const main = document.createElement("div");
    main.className = "top-file-main";

    const name = document.createElement("div");
    name.className = "top-file-name";
    name.textContent = file.name;

    const path = document.createElement("div");
    path.className = "top-file-path";
    path.textContent = file.path || file.name;

    const size = document.createElement("div");
    size.className = "top-file-size";
    size.textContent = formatBytes(file.size);

    main.append(name, path);
    row.append(main, size);
    el.topFilesBody.appendChild(row);
  });
}

function renderDetails() {
  const node = state.selected || state.current;
  el.selectedSize.textContent = formatBytes(state.current.size);
  el.selectedItems.textContent = formatCount(state.current.items);
  el.selectedFiles.textContent = formatCount(state.current.files);
  el.detailName.textContent = node.name;
  el.detailPath.textContent = node.path || node.name;
  el.detailStats.textContent = "";
  const stats = [
    formatBytes(node.size),
    pct(node.size, DATA.size),
    node.type,
    node.ext || "directory",
    `${formatCount(node.items)} items`,
    `${formatCount(node.files)} files`
  ];
  const modified = formatModifiedTime(node.mtime);
  if (modified) stats.push(`Modified ${modified}`);
  stats.forEach(value => {
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.textContent = value;
    el.detailStats.appendChild(pill);
  });
}

function showTooltip(event, node) {
  el.tooltip.innerHTML = `<strong>${escapeHtml(node.name)}</strong>${escapeHtml(formatBytes(node.size))} · ${escapeHtml(pct(node.size, DATA.size))}<br>${escapeHtml(node.path || node.name)}`;
  el.tooltip.style.left = `${event.clientX}px`;
  el.tooltip.style.top = `${event.clientY}px`;
  el.tooltip.style.display = "block";
}

function hideTooltip() {
  el.tooltip.style.display = "none";
}

function setTheme(theme, persist = true) {
  const normalized = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = normalized;
  el.themeToggle.checked = normalized === "light";
  el.themeToggle.setAttribute("aria-checked", String(el.themeToggle.checked));
  if (!persist) return;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, normalized);
  } catch (error) {
    // The report still works when localStorage is unavailable, such as in strict file contexts.
  }
}

function openHelpPage() {
  hideTooltip();
  el.helpPage.hidden = false;
  el.helpCloseButton.focus();
}

function closeHelpPage(focusHelpButton = true) {
  el.helpPage.hidden = true;
  if (focusHelpButton) el.helpButton.focus();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[char]));
}

function render() {
  renderCrumbs();
  renderTree();
  renderHomePanel();
  renderTreemap();
  renderDetails();
  setSelected(state.selected);
}

function renderSafely() {
  try {
    render();
  } catch (error) {
    showRenderError(error);
  }
}

function showRenderError(error) {
  console.error(error);
  el.tree.textContent = "";
  const row = document.createElement("div");
  row.className = "row";
  row.textContent = "Unable to render this directory";
  el.tree.appendChild(row);

  el.treemap.textContent = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "Unable to render this directory";
  el.treemap.appendChild(empty);

  el.detailName.textContent = state.current.name || "Render error";
  el.detailPath.textContent = error && error.message ? error.message : String(error);
  el.detailStats.textContent = "";
}

function prepareReportData(root) {
  byId.clear();
  byPath.clear();
  parent.clear();
  searchIndex.length = 0;
  searchCandidateIndex.clear();
  closeSearchResults();
  nextNodeId = 0;
  DATA = root;
  walk(DATA, null);
  state.current = DATA;
  state.selected = DATA;
}

function showLoadError(error) {
  console.error(error);
  el.tree.textContent = "";
  const row = document.createElement("div");
  row.className = "row";
  row.textContent = "Unable to load report data";
  el.tree.appendChild(row);

  el.treemap.textContent = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "Unable to load report data";
  el.treemap.appendChild(empty);

  el.content.classList.remove("home");
  el.homeResizer.hidden = true;
  el.topFiles.hidden = true;
  el.detailName.textContent = "Unable to load report";
  el.detailPath.textContent = error && error.message ? error.message : String(error);
  el.detailStats.textContent = "";
}

let isRescanning = false;
let nextScanTimestamp = null;
let schedulingTimer = null;

function startSchedulingCountdown(nextScanTimeVal, lastScanTimeVal) {
  if (schedulingTimer) clearInterval(schedulingTimer);
  
  const infoContainer = document.getElementById("scanSchedulingInfo");
  if (!infoContainer) return;
  infoContainer.hidden = false;
  
  const generatedEl = document.querySelector(".footer .generated");
  if (generatedEl) generatedEl.style.display = "none";
  
  const lastScanEl = document.getElementById("lastScanTime");
  if (lastScanEl && lastScanTimeVal) {
    lastScanEl.textContent = formatListModifiedTime(lastScanTimeVal);
  }
  
  const nextScanEl = document.getElementById("nextScanTime");
  if (!nextScanEl) return;
  
  if (!nextScanTimeVal) {
    nextScanEl.textContent = "Disabled";
    return;
  }
  
  const nextDate = dateFromModifiedValue(nextScanTimeVal);
  if (!nextDate) {
    nextScanEl.textContent = String(nextScanTimeVal);
    return;
  }
  
  nextScanTimestamp = nextDate.getTime();
  const nextScanTimeFormatted = formatListModifiedTime(nextScanTimeVal);
  
  function updateCountdown() {
    if (isRescanning) {
      nextScanEl.textContent = "Scanning...";
      return;
    }
    
    const now = Date.now();
    const diff = nextScanTimestamp - now;
    if (diff <= 0) {
      nextScanEl.textContent = `${nextScanTimeFormatted} (Scanning soon...)`;
      // If we just hit 0, trigger a status check to detect the scan starting
      if (Math.abs(diff) < 2000) {
        if (!updateCountdown._lastTrigger || now - updateCountdown._lastTrigger > 5000) {
          updateCountdown._lastTrigger = now;
          checkRescanStatus();
        }
      }
      return;
    }
    
    const seconds = Math.floor((diff / 1000) % 60);
    const minutes = Math.floor((diff / (1000 * 60)) % 60);
    const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    let timeString = "";
    if (days > 0) timeString += `${days}d `;
    if (hours > 0 || days > 0) timeString += `${hours}h `;
    if (minutes > 0 || hours > 0 || days > 0) timeString += `${minutes}m `;
    timeString += `${seconds}s`;
    
    nextScanEl.textContent = `${nextScanTimeFormatted} (in ${timeString})`;
  }
  
  updateCountdown();
  schedulingTimer = setInterval(updateCountdown, 1000);
}

async function checkRescanStatus() {
  try {
    const response = await fetch("/api/status");
    if (!response.ok) {
      setTimeout(checkRescanStatus, 10000);
      return;
    }
    const data = await response.json();
    
    if (data.last_scan_time || data.next_scan_time) {
      startSchedulingCountdown(data.next_scan_time, data.last_scan_time);
    }
    
    if (data.status === "scanning") {
      setRescanningState(true);
      setTimeout(checkRescanStatus, 1500);
    } else {
      if (isRescanning) {
        setRescanningState(false);
        window.location.reload();
        return;
      }
      setRescanningState(false);
      // Poll every 10 seconds when idle to stay synchronized with periodic scans
      setTimeout(checkRescanStatus, 10000);
    }
  } catch (error) {
    console.error("Failed to fetch scan status:", error);
    setRescanningState(false);
    // Poll again in 10s if we failed to reach the server
    setTimeout(checkRescanStatus, 10000);
  }
}

async function triggerRescan() {
  if (isRescanning) return;
  setRescanningState(true);
  try {
    const response = await fetch("/api/rescan", { method: "POST" });
    if (response.status === 202) {
      setTimeout(checkRescanStatus, 1000);
    } else if (response.status === 499 || response.status === 409) {
      setTimeout(checkRescanStatus, 500);
    } else {
      alert("Failed to start scan. Server status: " + response.status);
      setRescanningState(false);
    }
  } catch (error) {
    console.error("Failed to trigger rescan:", error);
    alert("Failed to trigger rescan. Please check if the server is running.");
    setRescanningState(false);
  }
}

function setRescanningState(active) {
  isRescanning = active;
  const btn = document.getElementById("rescanButton");
  if (!btn) return;
  btn.disabled = active;
  btn.classList.toggle("spinning", active);
  btn.title = active ? "Scanning in progress..." : "Trigger manual rescan";
}

async function initRescanUI() {
  const btn = document.getElementById("rescanButton");
  if (!btn) return;
  try {
    const response = await fetch("/api/status");
    if (response.ok) {
      btn.addEventListener("click", triggerRescan);
      checkRescanStatus();
    } else {
      btn.remove();
    }
  } catch (e) {
    btn.remove();
  }
}

async function initReport() {
  setTheme(document.documentElement.dataset.theme, false);
  state.treemapTileCap = readStoredTreemapTileCap();
  el.treemapTileCap.value = String(state.treemapTileCap);
  state.visibleColumns = readStoredTreeColumns();
  applyTreeColumnLayout();
  syncMainPaneSize();

  try {
    const root = await loadReportData(REPORT_DATA_PAYLOAD);
    prepareReportData(root);
    const initialNode = nodeFromLocationHash();
    if (initialNode) {
      state.current = initialNode;
      state.selected = initialNode;
      syncUrlToCurrent(initialNode, true);
    }
    renderSafely();
    initRescanUI();
  } catch (error) {
    showLoadError(error);
  }
}

el.themeToggle.addEventListener("change", event => {
  setTheme(event.target.checked ? "light" : "dark");
});
el.helpButton.addEventListener("click", openHelpPage);
el.helpCloseButton.addEventListener("click", () => closeHelpPage());
el.helpPage.addEventListener("click", event => {
  if (event.target === el.helpPage) closeHelpPage();
});
el.mainResizer.addEventListener("pointerdown", beginMainResize);
el.mainResizer.addEventListener("keydown", handleMainResizerKey);
el.homeResizer.addEventListener("pointerdown", beginHomeResize);
el.homeResizer.addEventListener("keydown", handleHomeResizerKey);
el.searchShortcut.addEventListener("click", focusSearch);
el.searchInput.addEventListener("input", scheduleSearchResults);
el.searchInput.addEventListener("focus", () => renderSearchResultsForQuery(el.searchInput.value));
el.searchInput.addEventListener("click", selectSearchInputText);
el.searchInput.addEventListener("keydown", event => {
  if (event.key === "ArrowDown") {
    event.preventDefault();
    if (!searchResults.length) renderSearchResultsForQuery(el.searchInput.value);
    moveSearchActiveResult(1);
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    if (!searchResults.length) renderSearchResultsForQuery(el.searchInput.value);
    moveSearchActiveResult(-1);
  } else if (event.key === "Enter") {
    event.preventDefault();
    if (searchTimer) {
      clearTimeout(searchTimer);
      searchTimer = 0;
      renderSearchResultsForQuery(el.searchInput.value);
    }
    activateSearchResult();
  } else if (event.key === "Escape") {
    event.preventDefault();
    closeSearchResults();
    el.searchInput.blur();
  }
});
el.topFilesLimit.addEventListener("change", event => {
  state.topFilesLimit = normalizeTopFilesLimit(event.target.value);
  renderHomePanel();
  setSelected(state.selected);
});
el.treemapTileCap.addEventListener("change", event => {
  state.treemapTileCap = normalizeTreemapTileCap(event.target.value);
  el.treemapTileCap.value = String(state.treemapTileCap);
  storeTreemapTileCap(state.treemapTileCap);
  renderTreemap();
  setSelected(state.selected);
});
el.tree.addEventListener("scroll", () => renderVisibleTreeRows(), { passive: true });
document.addEventListener("click", event => {
  if (
    event.target &&
    typeof event.target.closest === "function" &&
    !event.target.closest(".search")
  ) {
    closeSearchResults();
  }
  if (
    event.target &&
    typeof event.target.closest === "function" &&
    (event.target.closest(".tree-columns-menu") || event.target.closest(".tree-columns-btn"))
  ) return;
  closeTreeColumnsMenu();
});
el.sidebar.addEventListener("wheel", event => {
  if (event.target && event.target.closest(".tree")) return;
  if (!event.deltaY && !event.deltaX) return;
  el.tree.scrollTop += event.deltaY;
  el.tree.scrollLeft += event.deltaX;
  event.preventDefault();
}, { passive: false });
window.addEventListener("resize", () => {
  syncMainPaneSize();
  if (!DATA) return;
  if (state.current === DATA) syncHomePaneSize();
  renderVisibleTreeRows();
  renderTreemap();
});
window.addEventListener("popstate", applyLocationHash);
window.addEventListener("hashchange", applyLocationHash);

function isTextEditingTarget(target) {
  if (!target) return false;
  const tagName = target.tagName;
  return target.isContentEditable ||
    tagName === "INPUT" ||
    tagName === "TEXTAREA" ||
    tagName === "SELECT";
}

function scrollTreeSelectionIntoView(node) {
  if (!node) return;
  const row = document.querySelector(`.tree .row[data-id="${node.id}"]`);
  if (row && typeof row.scrollIntoView === "function") {
    row.scrollIntoView({ block: "nearest" });
    return;
  }

  const children = currentTreeChildren();
  const index = children.findIndex(child => child.id === node.id);
  if (index < 0) return;

  const header = el.tree.querySelector(".tree-header");
  const headerHeight = header ? header.offsetHeight : 0;
  const rowTop = headerHeight + index * TREE_ROW_HEIGHT;
  const rowBottom = rowTop + TREE_ROW_HEIGHT;
  const visibleTop = el.tree.scrollTop + headerHeight;
  const visibleBottom = el.tree.scrollTop + el.tree.clientHeight;
  if (rowTop < visibleTop) {
    el.tree.scrollTop = Math.max(0, rowTop - headerHeight);
  } else if (rowBottom > visibleBottom) {
    el.tree.scrollTop = rowBottom - el.tree.clientHeight;
  }
  renderVisibleTreeRows();
}

function setListSelectionByIndex(index) {
  if (!state.current) return;
  const children = currentTreeChildren();
  if (!children.length) return;
  const clamped = Math.max(0, Math.min(children.length - 1, index));
  const node = children[clamped];
  setSelected(node);
  scrollTreeSelectionIntoView(node);
}

function moveListSelection(delta) {
  if (!state.current) return;
  const children = currentTreeChildren();
  if (!children.length) return;
  let index = children.findIndex(child => state.selected && child.id === state.selected.id);
  if (index < 0) {
    index = delta > 0 ? 0 : children.length - 1;
  } else {
    index += delta;
  }
  setListSelectionByIndex(index);
}

function treePageRowCount() {
  const header = el.tree.querySelector(".tree-header");
  const headerHeight = header ? header.offsetHeight : 0;
  const availableHeight = Math.max(TREE_ROW_HEIGHT, el.tree.clientHeight - headerHeight);
  return Math.max(1, Math.floor(availableHeight / TREE_ROW_HEIGHT));
}

function openSelectedDirectory() {
  if (state.selected && state.selected.type === "dir") {
    setCurrent(state.selected);
  }
}

function handleListKey(event) {
  if (handleSortShortcut(event)) return true;
  if (event.key === "ArrowDown") {
    event.preventDefault();
    moveListSelection(1);
    return true;
  }
  if (event.key === "ArrowUp") {
    event.preventDefault();
    moveListSelection(-1);
    return true;
  }
  if (event.key === "PageDown") {
    event.preventDefault();
    moveListSelection(treePageRowCount());
    return true;
  }
  if (event.key === "PageUp") {
    event.preventDefault();
    moveListSelection(-treePageRowCount());
    return true;
  }
  if (event.key === "Home") {
    event.preventDefault();
    setListSelectionByIndex(0);
    return true;
  }
  if (event.key === "End") {
    event.preventDefault();
    setListSelectionByIndex(currentTreeChildren().length - 1);
    return true;
  }
  if (event.key === "Enter" || event.key === "ArrowRight") {
    event.preventDefault();
    openSelectedDirectory();
    return true;
  }
  return false;
}

document.addEventListener("keydown", event => {
  if (event.defaultPrevented) return;
  if (
    DATA &&
    el.helpPage.hidden &&
    !event.altKey &&
    (event.ctrlKey || event.metaKey) &&
    event.key.toLowerCase() === "f"
  ) {
    event.preventDefault();
    focusSearch();
    return;
  }
  if (event.key === "Escape" && !el.helpPage.hidden) {
    event.preventDefault();
    closeHelpPage();
    return;
  }
  if (event.key === "Escape" && closeTreeColumnsMenu(true)) {
    event.preventDefault();
    return;
  }
  if (!el.helpPage.hidden) return;
  if (isTextEditingTarget(event.target)) return;
  if (event.key === "?" && !event.ctrlKey && !event.altKey && !event.metaKey) {
    event.preventDefault();
    openHelpPage();
    return;
  }
  if (event.key === "/" && !event.ctrlKey && !event.altKey && !event.metaKey) {
    event.preventDefault();
    focusSearch();
    return;
  }
  if (!DATA) return;
  if (event.key === "Backspace" || event.key === "ArrowLeft") {
    event.preventDefault();
    goParent();
    return;
  }
  handleListKey(event);
});

initReport();