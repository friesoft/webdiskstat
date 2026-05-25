#!/usr/bin/env python3
"""
Convert JSON exported by `gdu -o-` or `ncdu -o-` into a self-contained
WinDirStat-like HTML report.

Examples:
  gdu -o- /home | ./webdiskstat.py -o report.html
  ncdu -o- /home | ./webdiskstat.py --input-type ncdu -o report.html
  zcat report.json.gz | ./webdiskstat.py -o report.html
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import gzip
import hashlib
import html
import json
import mimetypes
import posixpath
import re
import secrets
import sys
from pathlib import Path
from typing import Any


APP_TITLE = "webdiskstat"
REPORT_SIZE_PLACEHOLDER = "__WEBDISKSTAT_REPORT_SIZE__"
ENCRYPTION_AAD = b"webdiskstat-report-data-v1"
ENCRYPTION_ALGORITHM = "ChaCha20-Poly1305"
PBKDF2_ITERATIONS = 310_000
FAVICON_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="14" fill="#111827"/>
<path d="M15 12h34l7 17v20a7 7 0 0 1-7 7H15a7 7 0 0 1-7-7V29l7-17Z" fill="#20252c" stroke="#7bd7ff" stroke-width="3" stroke-linejoin="round"/>
<path d="M9 29h46" stroke="#475569" stroke-width="3"/>
<rect x="18" y="18" width="24" height="5" rx="2.5" fill="#64748b"/>
<circle cx="48" cy="20.5" r="2.5" fill="#65e4c4"/>
<rect x="15" y="35" width="16" height="13" rx="3" fill="#65e4c4"/>
<rect x="34" y="35" width="9" height="13" rx="3" fill="#38bdf8"/>
<rect x="46" y="35" width="7" height="13" rx="3" fill="#f59e0b"/>
<rect x="15" y="51" width="38" height="2" rx="1" fill="#0f172a" opacity=".85"/>
</svg>
""".strip()
FAVICON_HREF = (
    "data:image/svg+xml;base64,"
    + base64.b64encode(FAVICON_SVG.encode("utf-8")).decode("ascii")
)

CHILD_KEYS = (
    "items",
    "Items",
    "children",
    "Children",
    "entries",
    "Entries",
    "files",
    "Files",
    "dirs",
    "Dirs",
    "nodes",
    "Nodes",
)

NAME_KEYS = ("name", "Name", "path", "Path", "fullPath", "FullPath")
PATH_KEYS = ("path", "Path", "fullPath", "FullPath")
SIZE_KEYS = (
    "usage",
    "Usage",
    "size",
    "Size",
    "diskUsage",
    "DiskUsage",
    "disk_usage",
    "dsize",
    "Dsize",
    "asize",
    "Asize",
    "blocks",
    "Blocks",
    "apparentSize",
    "ApparentSize",
    "apparent_size",
    "total",
    "Total",
)
DIR_KEYS = ("isDir", "IsDir", "dir", "Dir", "directory", "Directory")
MTIME_KEYS = ("mtime", "Mtime", "modTime", "ModTime", "modified", "Modified")
FLAG_KEYS = ("flag", "Flag", "flags", "Flags")


class NoInputError(ValueError):
    """Raised when stdin was selected but no JSON was provided."""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a static WinDirStat-like web report from gdu or ncdu JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  gdu -o- / | %(prog)s -o webdiskstat.html\n"
            "  ncdu -o- / | %(prog)s --input-type ncdu -o webdiskstat.html\n"
            "  zcat report.json.gz | %(prog)s -o report.html\n"
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Input JSON file, .gz file, or '-' for stdin. Defaults to stdin.",
    )
    parser.add_argument(
        "--input-type",
        choices=("gdu", "ncdu"),
        default="gdu",
        help="Input JSON format. Defaults to gdu.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="webdiskstat.html",
        help="HTML output path, or '-' for stdout. Defaults to webdiskstat.html.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Encrypt embedded report data with this password. Defaults to unencrypted.",
    )
    args = parser.parse_args()

    if args.password == "":
        parser.error("--password must not be empty")

    if args.input == "-" and sys.stdin.isatty():
        print_no_input_help(parser)
        return 2

    try:
        raw = read_json(args.input)
        root = normalize_export(raw, args.input_type)
        report = render_report(root, args.password)
    except NoInputError:
        print_no_input_help(parser)
        return 2
    except Exception as exc:
        print(f"webdiskstat: {exc}", file=sys.stderr)
        return 1

    output_path = write_report(report, args.output)
    if args.output == "-":
        return 0

    print(f"Wrote {output_path}", file=sys.stderr)
    return 0


def read_json(source: str) -> Any:
    if source == "-":
        text = sys.stdin.buffer.read()
        if not text.strip():
            raise NoInputError("stdin is empty")
        if text.startswith(b"\x1f\x8b"):
            text = gzip.decompress(text)
        return json.loads(text)

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"{source!r} does not exist")

    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def print_no_input_help(parser: argparse.ArgumentParser) -> None:
    print("No input provided. Pipe gdu or ncdu JSON into the script or pass a saved JSON file.", file=sys.stderr)
    print(file=sys.stderr)
    parser.print_help(file=sys.stderr)


def write_report(report: str, output: str) -> Path:
    if output == "-":
        sys.stdout.write(report)
        return Path("<stdout>")

    path = Path(output).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
    return path


def normalize_export(raw: Any, input_type: str = "gdu") -> dict[str, Any]:
    if input_type not in ("gdu", "ncdu"):
        raise ValueError(f"unsupported input type: {input_type}")

    if is_export_array(raw):
        if input_type == "ncdu":
            validate_ncdu_export(raw)
        raw = raw[3]
    elif input_type == "ncdu":
        raise ValueError("expected ncdu JSON export array from `ncdu -o-`")

    if isinstance(raw, list):
        if is_sequence_node(raw):
            root = normalize_node(raw, "root", "", input_type)
            add_totals(root)
            return root

        children = [normalize_node(item, f"item-{index}", "", input_type) for index, item in enumerate(raw)]
        root = {
            "name": "root",
            "path": "root",
            "size": sum(child["size"] for child in children),
            "type": "dir",
            "ext": "",
            "children": children,
        }
        add_totals(root)
        return root

    if isinstance(raw, dict):
        node = unwrap_possible_root(raw)
        root = normalize_node(node, "root", "", input_type)
        add_totals(root)
        return root

    raise ValueError("expected a JSON object or array")


def is_export_array(raw: Any) -> bool:
    return (
        isinstance(raw, list)
        and len(raw) >= 4
        and isinstance(raw[0], int)
        and isinstance(raw[1], int)
        and isinstance(raw[2], dict)
        and isinstance(raw[3], (dict, list))
    )


def validate_ncdu_export(raw: list[Any]) -> None:
    if raw[0] != 1:
        raise ValueError(f"unsupported ncdu export major version: {raw[0]}")
    if not isinstance(raw[1], int):
        raise ValueError("invalid ncdu export minor version")
    if not isinstance(raw[3], list) or not is_sequence_node(raw[3]):
        raise ValueError("invalid ncdu export directory tree")


def unwrap_possible_root(raw: dict[str, Any]) -> Any:
    if looks_like_node(raw):
        return raw

    for key in ("root", "Root", "data", "Data", "scan", "Scan", "tree", "Tree"):
        value = raw.get(key)
        if isinstance(value, (dict, list)):
            return value

    dict_values = [value for value in raw.values() if isinstance(value, dict)]
    if len(dict_values) == 1:
        return dict_values[0]

    return raw


def looks_like_node(value: dict[str, Any]) -> bool:
    return any(key in value for key in NAME_KEYS + SIZE_KEYS + CHILD_KEYS)


def is_sequence_node(raw: Any) -> bool:
    return isinstance(raw, list) and bool(raw) and isinstance(raw[0], dict) and looks_like_node(raw[0])


def normalize_node(
    raw: Any,
    fallback_name: str,
    parent_path: str,
    input_type: str = "gdu",
) -> dict[str, Any]:
    if isinstance(raw, dict):
        mapped = normalize_mapping_node(raw, fallback_name, parent_path, input_type)
        return mapped

    if isinstance(raw, list):
        if is_sequence_node(raw):
            return normalize_sequence_node(raw, fallback_name, parent_path, input_type)

        children = [normalize_node(item, fallback_name, parent_path, input_type) for item in raw]
        return {
            "name": fallback_name,
            "path": make_path(parent_path, fallback_name),
            "size": sum(child["size"] for child in children),
            "type": "dir",
            "ext": "",
            "children": children,
        }

    size = numberish(raw)
    return {
        "name": fallback_name,
        "path": make_path(parent_path, fallback_name),
        "size": size,
        "type": "file",
        "ext": extension_for(fallback_name),
        "children": [],
    }


def normalize_sequence_node(
    raw: list[Any],
    fallback_name: str,
    parent_path: str,
    input_type: str = "gdu",
) -> dict[str, Any]:
    info = raw[0]
    name_value = first_string(info, NAME_KEYS)
    path_value = first_string(info, PATH_KEYS)
    if path_value and (not name_value or name_value == path_value):
        name = display_name_from_path(path_value)
    else:
        name = name_value or fallback_name
    path = path_value or make_path(parent_path, name)

    children = [
        normalize_node(child, f"item-{index}", path, input_type)
        for index, child in enumerate(raw[1:])
    ]
    size = first_number(info, SIZE_KEYS)
    child_size = sum(child["size"] for child in children)
    if input_type == "ncdu" and children:
        size += child_size
    elif size <= 0:
        size = child_size

    node = {
        "name": name,
        "path": path,
        "size": size,
        "type": "dir" if children or first_bool(info, DIR_KEYS) else "file",
        "ext": "",
        "children": sorted(children, key=lambda child: child["size"], reverse=True),
    }

    mtime = first_scalar(info, MTIME_KEYS)
    if mtime not in ("", None):
        node["mtime"] = str(mtime)

    flag = first_string(info, FLAG_KEYS)
    if flag:
        node["flag"] = flag

    return node


def normalize_mapping_node(
    raw: dict[str, Any],
    fallback_name: str,
    parent_path: str,
    input_type: str = "gdu",
) -> dict[str, Any]:
    children_raw = extract_children(raw)
    path_value = first_string(raw, PATH_KEYS)
    name_value = first_string(raw, NAME_KEYS)

    if path_value and (not name_value or name_value == path_value):
        name = display_name_from_path(path_value)
    else:
        name = name_value or fallback_name

    path = path_value or make_path(parent_path, name)
    if parent_path and path == name:
        path = make_path(parent_path, name)

    children = []
    if isinstance(children_raw, dict):
        for child_name, child_value in children_raw.items():
            children.append(normalize_node(child_value, str(child_name), path, input_type))
    elif isinstance(children_raw, list):
        for index, child in enumerate(children_raw):
            children.append(normalize_node(child, f"item-{index}", path, input_type))
    elif children_raw is None:
        children = extract_mapping_children(raw, path, input_type)

    size = first_number(raw, SIZE_KEYS)
    if size <= 0 and children:
        size = sum(child["size"] for child in children)

    is_dir = bool(children) or first_bool(raw, DIR_KEYS)
    node_type = "dir" if is_dir else "file"

    node = {
        "name": name,
        "path": path,
        "size": size,
        "type": node_type,
        "ext": "" if is_dir else extension_for(name),
        "children": sorted(children, key=lambda child: child["size"], reverse=True),
    }

    mtime = first_scalar(raw, MTIME_KEYS)
    if mtime not in ("", None):
        node["mtime"] = str(mtime)

    flag = first_string(raw, FLAG_KEYS)
    if flag:
        node["flag"] = flag

    mime = mimetypes.guess_type(name)[0]
    if mime:
        node["mime"] = mime

    return node


def extract_children(raw: dict[str, Any]) -> Any | None:
    for key in CHILD_KEYS:
        value = raw.get(key)
        if isinstance(value, (list, dict)):
            return value

    for key, value in raw.items():
        if key in NAME_KEYS + SIZE_KEYS + PATH_KEYS + DIR_KEYS + MTIME_KEYS + FLAG_KEYS:
            continue
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            return value

    return None


def extract_mapping_children(
    raw: dict[str, Any],
    parent_path: str,
    input_type: str = "gdu",
) -> list[dict[str, Any]]:
    if looks_like_node(raw):
        return []

    children = []
    for key, value in raw.items():
        if isinstance(value, (dict, list, int, float)):
            children.append(normalize_node(value, str(key), parent_path, input_type))
    return children


def add_totals(root: dict[str, Any]) -> None:
    next_id = 0

    def visit(node: dict[str, Any], depth: int) -> tuple[int, int]:
        nonlocal next_id
        node["id"] = next_id
        next_id += 1
        node["depth"] = depth

        total_count = 1
        file_count = 0 if node["type"] == "dir" else 1
        for child in node.get("children", []):
            child_count, child_files = visit(child, depth + 1)
            total_count += child_count
            file_count += child_files
        node["items"] = total_count - 1
        node["files"] = file_count
        return total_count, file_count

    visit(root, 0)


def first_string(raw: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def first_scalar(raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, (str, int, float)) and value != "":
            return value
    return ""


def first_number(raw: dict[str, Any], keys: tuple[str, ...]) -> int:
    for key in keys:
        value = raw.get(key)
        number = numberish(value)
        if number > 0:
            return number
    return 0


def first_bool(raw: dict[str, Any], keys: tuple[str, ...]) -> bool:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, bool):
            return value
    return False


def numberish(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    if isinstance(value, str):
        cleaned = value.strip().replace(",", "")
        if re.fullmatch(r"\d+(\.\d+)?", cleaned):
            return max(0, int(float(cleaned)))
    return 0


def display_name_from_path(path: str) -> str:
    trimmed = path.rstrip("/")
    if not trimmed:
        return path or "root"
    return posixpath.basename(trimmed) or trimmed


def make_path(parent: str, name: str) -> str:
    if not parent:
        return name
    if parent == "/":
        return "/" + name.strip("/")
    return parent.rstrip("/") + "/" + name.strip("/")


def extension_for(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    if "." not in base or base.startswith(".") and base.count(".") == 1:
        return "[no extension]"
    ext = base.rsplit(".", 1)[-1].lower()
    return "." + ext if ext else "[no extension]"


def serialize_report_data(root: dict[str, Any]) -> list[Any]:
    strings: list[str] = []
    string_indexes: dict[str, int] = {}

    def intern(value: Any) -> int:
        if value in ("", None):
            return -1
        text = str(value)
        index = string_indexes.get(text)
        if index is not None:
            return index
        index = len(strings)
        strings.append(text)
        string_indexes[text] = index
        return index

    def pack(node: dict[str, Any], parent_path: str) -> list[Any]:
        name = str(node.get("name") or "")
        path = str(node.get("path") or make_path(parent_path, name))
        expected_path = make_path(parent_path, name)
        node_type = 1 if node.get("type") == "dir" else 0
        children = [pack(child, path) for child in node.get("children", [])]
        return [
            intern(name),
            -1 if path == expected_path else intern(path),
            int(node.get("size") or 0),
            node_type,
            intern(node.get("ext") or ""),
            intern(node.get("mtime") or ""),
            intern(node.get("mime") or ""),
            intern(node.get("flag") or ""),
            children,
        ]

    return [strings, pack(root, "")]


def script_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def compressed_script_json_bytes(value: Any) -> bytes:
    raw = script_json(value).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def report_data_payload(root: dict[str, Any], password: str | None) -> str:
    compressed = compressed_script_json_bytes(serialize_report_data(root))
    if password is None:
        return script_json({
            "encrypted": False,
            "payload": base64.b64encode(compressed).decode("ascii"),
        })

    encrypted = encrypt_report_data(compressed, password)
    return script_json(encrypted)


def encrypt_report_data(plaintext: bytes, password: str) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, ENCRYPTION_AAD)
    return {
        "encrypted": True,
        "algorithm": ENCRYPTION_ALGORITHM,
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "aad": ENCRYPTION_AAD.decode("ascii"),
        "payload": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("encryption key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("encryption nonce must be 12 bytes")

    poly_key = chacha20_block(key, nonce, 0)[:32]
    ciphertext = chacha20_xor(key, nonce, 1, plaintext)
    tag = poly1305_mac(poly1305_aead_data(aad, ciphertext), poly_key)
    return ciphertext, tag


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    output = bytearray(len(data))
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, nonce, counter)
        chunk = data[offset:offset + 64]
        for index, value in enumerate(chunk):
            output[offset + index] = value ^ block[index]
        counter = (counter + 1) & 0xFFFFFFFF
        if counter == 0 and offset + 64 < len(data):
            raise ValueError("report data is too large to encrypt with one nonce")
    return bytes(output)


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    def word(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 4], "little")

    state = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *[word(key, offset) for offset in range(0, 32, 4)],
        counter & 0xFFFFFFFF,
        *[word(nonce, offset) for offset in range(0, 12, 4)],
    ]
    working = state[:]

    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    return b"".join(
        ((working[index] + state[index]) & 0xFFFFFFFF).to_bytes(4, "little")
        for index in range(16)
    )


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate_left(state[b] ^ state[c], 7)


def rotate_left(value: int, bits: int) -> int:
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))


def poly1305_aead_data(aad: bytes, ciphertext: bytes) -> bytes:
    def padding(length: int) -> bytes:
        return b"\x00" * ((16 - length % 16) % 16)

    return b"".join((
        aad,
        padding(len(aad)),
        ciphertext,
        padding(len(ciphertext)),
        len(aad).to_bytes(8, "little"),
        len(ciphertext).to_bytes(8, "little"),
    ))


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r = bytearray(key[:16])
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252

    r_value = int.from_bytes(r, "little")
    s_value = int.from_bytes(key[16:], "little")
    modulus = (1 << 130) - 5
    accumulator = 0

    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        number = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + number) * r_value) % modulus

    tag = (accumulator + s_value) % (1 << 128)
    return tag.to_bytes(16, "little")


def minify_css(css: str) -> str:
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    css = re.sub(r"\s+", " ", css)
    css = re.sub(r"\s*([{}:;,>])\s*", r"\1", css)
    css = re.sub(r";}", "}", css)
    return css.strip()


def optimize_report_html(report: str) -> str:
    blocks: list[str] = []

    def protect(pattern: str, text: str, transform=lambda value: value) -> str:
        def replace(match: re.Match[str]) -> str:
            token = f"@@WEBDISKSTAT_BLOCK_{len(blocks)}@@"
            blocks.append(transform(match.group(0)))
            return token

        return re.sub(pattern, replace, text, flags=re.S | re.I)

    def optimize_style(block: str) -> str:
        match = re.fullmatch(r"(<style>)(.*?)(</style>)", block, flags=re.S | re.I)
        if not match:
            return block
        return match.group(1) + minify_css(match.group(2)) + match.group(3)

    report = protect(r"<script>.*?</script>", report)
    report = protect(r"<style>.*?</style>", report, optimize_style)
    report = re.sub(r">\s+<", "><", report)
    report = "\n".join(line.strip() for line in report.splitlines() if line.strip())

    for index, block in enumerate(blocks):
        report = report.replace(f"@@WEBDISKSTAT_BLOCK_{index}@@", block)
    return report + "\n"


def format_report_file_size(size: int) -> str:
    units = ("bytes", "KiB", "MiB", "GiB")
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024

    if unit == "bytes":
        amount = f"{size:,}"
    elif value >= 100:
        amount = f"{value:,.0f}"
    elif value >= 10:
        amount = f"{value:,.1f}"
    else:
        amount = f"{value:,.2f}"
    return f"HTML file: {amount} {unit}"


def fill_report_size(report: str) -> str:
    size_label = format_report_file_size(len(report.encode("utf-8")))
    for _ in range(10):
        candidate = report.replace(REPORT_SIZE_PLACEHOLDER, size_label)
        next_label = format_report_file_size(len(candidate.encode("utf-8")))
        if next_label == size_label:
            return candidate
        size_label = next_label
    return report.replace(REPORT_SIZE_PLACEHOLDER, size_label)


def render_report(root: dict[str, Any], password: str | None = None) -> str:
    data = report_data_payload(root, password)
    encrypted_report = password is not None
    generated_at = datetime.now().astimezone()
    generated_iso = generated_at.isoformat(timespec="seconds")
    generated_display = generated_at.strftime("%Y-%m-%d %H:%M:%S %Z")
    escaped_title = html.escape(f"{APP_TITLE} - Generated {generated_display}")
    escaped_favicon = html.escape(FAVICON_HREF, quote=True)
    security_class = "encrypted" if encrypted_report else "plain"
    security_label = "Data encrypted" if encrypted_report else "Data not encrypted"
    security_title = (
        "Embedded scan data is encrypted and requires the report password."
        if encrypted_report
        else "Embedded scan data is not encrypted."
    )
    security_icon = (
        '<path d="M7 11V8a5 5 0 0 1 10 0v3"/>'
        if encrypted_report
        else '<path d="M8 11V8a4 4 0 0 1 7.6-1.8"/>'
    )
    footer_status = (
        f'<span class="report-security {security_class}" title="{html.escape(security_title)}">'
        '<svg class="security-icon" viewBox="0 0 24 24" aria-hidden="true">'
        f'{security_icon}'
        '<rect x="5" y="11" width="14" height="9" rx="2"/>'
        '<path d="M12 15v2"/>'
        '</svg>'
        f'<span>{html.escape(security_label)}</span>'
        '</span>'
    )


    # Load template assets using importlib.resources with local filesystem fallback
    try:
        from importlib import resources
        template_content = resources.files("webdiskstat.templates").joinpath("template.html").read_text(encoding="utf-8")
        css_content = resources.files("webdiskstat.templates").joinpath("style.css").read_text(encoding="utf-8")
        js_content = resources.files("webdiskstat.templates").joinpath("app.js").read_text(encoding="utf-8")
    except Exception:
        # Fallback to local files for direct checkouts/in-tree runs
        template_dir = Path(__file__).parent / "templates"
        template_content = (template_dir / "template.html").read_text(encoding="utf-8")
        css_content = (template_dir / "style.css").read_text(encoding="utf-8")
        js_content = (template_dir / "app.js").read_text(encoding="utf-8")

    # Substitute values
    report = template_content
    report = report.replace("{{TITLE}}", escaped_title)
    report = report.replace("{{FAVICON}}", escaped_favicon)
    report = report.replace("{{CSS}}", css_content)
    report = report.replace("{{FOOTER_STATUS}}", footer_status)
    report = report.replace("{{GENERATED_ISO}}", html.escape(generated_iso))
    report = report.replace("{{GENERATED_DISPLAY}}", html.escape(generated_display))
    report = report.replace("{{DATA}}", data)
    report = report.replace("{{JS}}", js_content)

    return fill_report_size(optimize_report_html(report))


if __name__ == "__main__":
    raise SystemExit(main())
