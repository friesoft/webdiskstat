#!/usr/bin/env python3
from __future__ import annotations

import base64
from datetime import datetime
import gzip
import html
import json
import posixpath
import re
from pathlib import Path
from typing import Any

APP_TITLE = "webdiskstat"
REPORT_SIZE_PLACEHOLDER = "__WEBDISKSTAT_REPORT_SIZE__"

CHILD_KEYS = (
    "items", "Items", "children", "Children", "entries", "Entries", "files", "Files", "dirs", "Dirs", "nodes", "Nodes"
)
NAME_KEYS = ("name", "Name", "path", "Path", "fullPath", "FullPath")
PATH_KEYS = ("path", "Path", "fullPath", "FullPath")
SIZE_KEYS = (
    "usage", "Usage", "size", "Size", "diskUsage", "DiskUsage", "disk_usage", "dsize", "Dsize", "asize", "Asize", "blocks", "Blocks", "apparentSize", "ApparentSize", "apparent_size", "total", "Total"
)
DIR_KEYS = ("isDir", "IsDir", "dir", "Dir", "directory", "Directory")
MTIME_KEYS = ("mtime", "Mtime", "modTime", "ModTime", "modified", "Modified")
FLAG_KEYS = ("flag", "Flag", "flags", "Flags")


def normalize_export(raw: Any, input_type: str = "gdu") -> dict[str, Any]:
    """Normalizes a GDU or NCDU JSON export (object or array) into a standard node tree structure."""
    if is_export_array(raw):
        raw = raw[3]

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
        return normalize_mapping_node(raw, fallback_name, parent_path, input_type)

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


def serialize_report_data(root: dict[str, Any]) -> list[Any]:
    """Packs the directory tree into a localized, compressed string-interned list structure."""
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


def report_data_payload(root: dict[str, Any]) -> dict[str, Any]:
    compressed = compressed_script_json_bytes(serialize_report_data(root))
    return {
        "payload": base64.b64encode(compressed).decode("ascii"),
    }
