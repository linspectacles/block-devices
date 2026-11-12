#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import ctypes
import ctypes.util
import os
import re

SECTOR_BYTES = 512


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, UnicodeError):
        return None


def _read_int(path: Path) -> Optional[int]:
    text = _read_text(path)
    if text is None or text == "":
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text)
        except ValueError:
            return None


def _read_bool01(path: Path) -> Optional[bool]:
    value = _read_int(path)
    if value is None:
        return None
    return bool(value)


def _children_names(path: Path) -> List[str]:
    try:
        return sorted((p.name for p in path.iterdir()), key=_natural_key)
    except OSError:
        return []


def _natural_key(value: str):
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", str(value))]


def format_bytes(value: Optional[int]) -> str:
    if value is None:
        return "Unavailable"
    units = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"]
    number = float(value)
    unit = 0
    while abs(number) >= 1024.0 and unit < len(units) - 1:
        number /= 1024.0
        unit += 1
    if unit == 0:
        return f"{int(number):,} bytes"
    return f"{number:.2f} {units[unit]}"


def format_count(value: Optional[int]) -> str:
    return "Unavailable" if value is None else f"{value:,}"


def format_bool(value: Optional[bool]) -> str:
    if value is None:
        return "Unavailable"
    return "Yes" if value else "No"


def _first_existing(paths: Iterable[Path]) -> Optional[str]:
    for path in paths:
        value = _read_text(path)
        if value not in {None, ""}:
            return value
    return None


@dataclass
class CollectionResult:
    records: List[Dict[str, Any]]
    warnings: List[str]


class BlkidProbe:
    """Tiny read-only libblkid wrapper used only for explicit Signatures… actions."""

    def __init__(self):
        self.lib = None
        name = ctypes.util.find_library("blkid")
        if not name:
            return
        try:
            lib = ctypes.CDLL(name)
            lib.blkid_new_probe_from_filename.argtypes = [ctypes.c_char_p]
            lib.blkid_new_probe_from_filename.restype = ctypes.c_void_p
            lib.blkid_free_probe.argtypes = [ctypes.c_void_p]
            lib.blkid_free_probe.restype = None
            lib.blkid_do_safeprobe.argtypes = [ctypes.c_void_p]
            lib.blkid_do_safeprobe.restype = ctypes.c_int
            lib.blkid_probe_numof_values.argtypes = [ctypes.c_void_p]
            lib.blkid_probe_numof_values.restype = ctypes.c_int
            lib.blkid_probe_get_value.argtypes = [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_char_p),
                ctypes.POINTER(ctypes.c_char_p),
                ctypes.POINTER(ctypes.c_size_t),
            ]
            lib.blkid_probe_get_value.restype = ctypes.c_int
            self.lib = lib
        except (OSError, AttributeError):
            self.lib = None

    @property
    def available(self) -> bool:
        return self.lib is not None

    def probe(self, devnode: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "source": "libblkid",
            "devnode": devnode,
            "available": self.available,
            "status": "",
            "values": {},
        }
        if self.lib is None:
            result["status"] = "libblkid is unavailable"
            return result
        if not devnode:
            result["status"] = "No device node was reported"
            return result

        probe = self.lib.blkid_new_probe_from_filename(os.fsencode(devnode))
        if not probe:
            result["status"] = "Could not open the selected device for read-only probing"
            return result
        try:
            rc = int(self.lib.blkid_do_safeprobe(probe))
            # 0 = result found, 1 = nothing found, -1 = error, -2 = ambiguous
            if rc == 1:
                result["status"] = "No recognized signature was reported"
            elif rc == -2:
                result["status"] = "Ambiguous signatures were reported"
            elif rc < 0:
                result["status"] = "The selected device could not be safely probed"
            else:
                result["status"] = "Probe completed"

            values: Dict[str, str] = {}
            count = max(0, int(self.lib.blkid_probe_numof_values(probe)))
            for index in range(count):
                name_p = ctypes.c_char_p()
                data_p = ctypes.c_char_p()
                length = ctypes.c_size_t()
                if self.lib.blkid_probe_get_value(
                    probe, index, ctypes.byref(name_p), ctypes.byref(data_p), ctypes.byref(length)
                ) != 0:
                    continue
                if not name_p:
                    continue
                name = name_p.value.decode("utf-8", errors="replace")
                if data_p:
                    raw = ctypes.string_at(data_p, length.value)
                    value = raw.decode("utf-8", errors="replace").rstrip("\x00")
                else:
                    value = ""
                values[name] = value
            result["values"] = values
            return result
        finally:
            self.lib.blkid_free_probe(probe)


class BlockDevicesProvider:
    """Read-only Linux block-device collector over /sys/class/block."""

    def __init__(self, sys_class_block: str = "/sys/class/block", dev_root: str = "/dev"):
        self.sys_class_block = Path(sys_class_block)
        self.dev_root = Path(dev_root)
        self.blkid = BlkidProbe()

    def list_devices(self) -> CollectionResult:
        warnings: List[str] = []
        if not self.sys_class_block.is_dir():
            return CollectionResult([], [f"{self.sys_class_block} is unavailable"])

        records: List[Dict[str, Any]] = []
        try:
            entries = sorted(self.sys_class_block.iterdir(), key=lambda p: _natural_key(p.name))
        except OSError as exc:
            return CollectionResult([], [f"Could not enumerate {self.sys_class_block}: {exc}"])

        for entry in entries:
            try:
                records.append(self._collect_device(entry))
            except Exception as exc:  # one device must not poison the inventory
                warnings.append(f"{entry.name}: {exc}")

        by_name = {r["name"]: r for r in records}
        for record in records:
            # Normalize direct partition children from collected parent relationships.
            record["partitions"] = sorted(
                [r["name"] for r in records if r.get("parent_device") == record["name"]],
                key=_natural_key,
            )
            # Relationship enrichments use only current snapshot records.
            record["related_records"] = {}
            for relation in ("holders", "slaves", "partitions"):
                record["related_records"][relation] = [
                    self._relationship_summary(by_name[name], relation)
                    for name in record.get(relation, [])
                    if name in by_name
                ]
            parent = record.get("parent_device")
            if parent and parent in by_name:
                record["related_records"]["parent"] = self._relationship_summary(by_name[parent], "parent")
            else:
                record["related_records"]["parent"] = None

        return CollectionResult(records, warnings)

    @staticmethod
    def _relationship_summary(record: Dict[str, Any], relation: str) -> Dict[str, Any]:
        label = {
            "holders": "Holding block device",
            "slaves": "Underlying block device",
            "partitions": "Partition child",
            "parent": "Parent block device",
        }.get(relation, relation)
        return {
            "name": record.get("name", ""),
            "category": record.get("category", ""),
            "major_minor": record.get("major_minor", ""),
            "size_bytes": record.get("size_bytes"),
            "relationship": label,
        }

    def _collect_device(self, entry: Path) -> Dict[str, Any]:
        name = entry.name
        resolved = entry.resolve(strict=False)
        dev_text = _read_text(entry / "dev") or ""
        major: Optional[int] = None
        minor: Optional[int] = None
        if ":" in dev_text:
            try:
                major, minor = (int(x) for x in dev_text.split(":", 1))
            except ValueError:
                major = minor = None

        size_sectors = _read_int(entry / "size")
        size_bytes = size_sectors * SECTOR_BYTES if size_sectors is not None else None
        ro = _read_bool01(entry / "ro")
        removable = _read_bool01(entry / "removable")
        partition_number = _read_int(entry / "partition")
        category = self._classify(entry, name, partition_number)

        parent_device = None
        if partition_number is not None:
            # For real /sys/class/block symlinks, a partition's resolved parent is its whole device.
            parent_candidate = resolved.parent.name
            if parent_candidate and parent_candidate != name:
                parent_device = parent_candidate

        start_sector = _read_int(entry / "start") if partition_number is not None else None
        sector_count = size_sectors if partition_number is not None else None
        end_sector = None
        if start_sector is not None and sector_count is not None:
            end_sector = start_sector if sector_count == 0 else start_sector + sector_count - 1
        start_offset_bytes = start_sector * SECTOR_BYTES if start_sector is not None else None
        length_bytes = sector_count * SECTOR_BYTES if sector_count is not None else None

        queue = entry / "queue"
        holders = _children_names(entry / "holders")
        slaves = _children_names(entry / "slaves")

        dm = self._collect_dm(entry)
        md, members = self._collect_md(entry)
        loop = self._collect_loop(entry)
        zram = self._collect_zram(entry)

        vendor = _first_existing((entry / "device/vendor", resolved / "device/vendor"))
        model = _first_existing((entry / "device/model", resolved / "device/model"))
        revision = _first_existing((entry / "device/rev", resolved / "device/rev", entry / "device/firmware_rev"))
        serial = _first_existing((entry / "device/serial", resolved / "device/serial"))
        wwid = _first_existing((entry / "wwid", entry / "device/wwid", resolved / "device/wwid"))

        access = "Unknown" if ro is None else ("Read-only" if ro else "Read/write")
        record: Dict[str, Any] = {
            "key": dev_text or str(resolved),
            "name": name,
            "category": category,
            "major": major,
            "minor": minor,
            "major_minor": dev_text or "Unavailable",
            "sysfs_path": str(resolved),
            "devnode": str(self.dev_root / name),
            "size_sectors": size_sectors,
            "size_bytes": size_bytes,
            "size": format_bytes(size_bytes),
            "access": access,
            "read_only": ro,
            "removable": removable,
            "rotational": _read_bool01(queue / "rotational"),
            "vendor": vendor,
            "model": model,
            "revision": revision,
            "serial": serial,
            "wwid": wwid,
            "parent_device": parent_device,
            "partition_number": partition_number,
            "start_sector": start_sector,
            "sector_count": sector_count,
            "end_sector": end_sector,
            "start_offset_bytes": start_offset_bytes,
            "length_bytes": length_bytes,
            "logical_block_size": _read_int(queue / "logical_block_size"),
            "physical_block_size": _read_int(queue / "physical_block_size"),
            "minimum_io_size": _read_int(queue / "minimum_io_size"),
            "optimal_io_size": _read_int(queue / "optimal_io_size"),
            "alignment_offset": _read_int(entry / "alignment_offset"),
            "discard_granularity": _read_int(queue / "discard_granularity"),
            "discard_max_bytes": _read_int(queue / "discard_max_bytes"),
            "scheduler": _read_text(queue / "scheduler"),
            "read_ahead_kb": _read_int(queue / "read_ahead_kb"),
            "nr_requests": _read_int(queue / "nr_requests"),
            "max_sectors_kb": _read_int(queue / "max_sectors_kb"),
            "write_cache": _read_text(queue / "write_cache"),
            "rq_affinity": _read_int(queue / "rq_affinity"),
            "nomerges": _read_int(queue / "nomerges"),
            "holders": holders,
            "slaves": slaves,
            "partitions": [],
            "dm": dm,
            "md": md,
            "md_members": members,
            "loop": loop,
            "zram": zram,
            "probe": None,
        }
        return record

    @staticmethod
    def _classify(entry: Path, name: str, partition_number: Optional[int]) -> str:
        if partition_number is not None:
            return "Partition"
        if (entry / "dm").is_dir():
            return "Device Mapper"
        if (entry / "md").is_dir():
            return "MD RAID"
        if name.startswith("loop"):
            return "Loop"
        if name.startswith("zram"):
            return "Zram"
        try:
            resolved = str(entry.resolve(strict=False))
        except OSError:
            resolved = ""
        if "/virtual/block/" in resolved:
            return "Other / Virtual"
        return "Disk"

    @staticmethod
    def _collect_dm(entry: Path) -> Optional[Dict[str, Any]]:
        dm = entry / "dm"
        if not dm.is_dir():
            return None
        return {
            "name": _read_text(dm / "name"),
            "uuid": _read_text(dm / "uuid"),
            "suspended": _read_bool01(dm / "suspended"),
        }

    @staticmethod
    def _collect_md(entry: Path) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        md = entry / "md"
        if not md.is_dir():
            return None, []
        members: List[Dict[str, Any]] = []
        try:
            member_dirs = sorted((p for p in md.iterdir() if p.name.startswith("dev-")), key=lambda p: _natural_key(p.name))
        except OSError:
            member_dirs = []
        active = failed = spare = 0
        for member in member_dirs:
            state = _read_text(member / "state")
            state_tokens = {token.strip() for token in (state or "").split(",") if token.strip()}
            if "faulty" in state_tokens or "blocked" in state_tokens:
                failed += 1
            elif "spare" in state_tokens:
                spare += 1
            elif state_tokens:
                active += 1
            dev_name = member.name[4:] if member.name.startswith("dev-") else member.name
            members.append({
                "device": dev_name,
                "slot": _read_int(member / "slot"),
                "state": state,
                "offset": _read_int(member / "offset"),
                "errors": _read_int(member / "errors"),
            })
        working = active + spare
        info = {
            "level": _read_text(md / "level"),
            "array_state": _read_text(md / "array_state"),
            "metadata_version": _read_text(md / "metadata_version"),
            "raid_devices": _read_int(md / "raid_disks"),
            "active_devices": active if members else None,
            "working_devices": working if members else None,
            "failed_devices": failed if members else None,
            "spare_devices": spare if members else None,
            "degraded_devices": _read_int(md / "degraded"),
            "component_size": _read_int(md / "component_size"),
            "chunk_size": _read_int(md / "chunk_size"),
            "layout": _read_text(md / "layout"),
            "sync_action": _read_text(md / "sync_action"),
            "sync_completed": _read_text(md / "sync_completed"),
            "mismatch_count": _read_int(md / "mismatch_cnt"),
        }
        return info, members

    @staticmethod
    def _collect_loop(entry: Path) -> Optional[Dict[str, Any]]:
        loop = entry / "loop"
        if not loop.is_dir():
            return None
        return {
            "backing_file": _read_text(loop / "backing_file"),
            "offset": _read_int(loop / "offset"),
            "size_limit": _read_int(loop / "sizelimit"),
            "autoclear": _read_bool01(loop / "autoclear"),
            "direct_io": _read_bool01(loop / "dio"),
        }

    @staticmethod
    def _collect_zram(entry: Path) -> Optional[Dict[str, Any]]:
        # zram attributes are exposed directly under the block object.
        if not entry.name.startswith("zram"):
            return None
        return {
            "algorithm": _read_text(entry / "comp_algorithm"),
            "disksize": _read_int(entry / "disksize"),
            "orig_data_size": _read_int(entry / "orig_data_size"),
            "compr_data_size": _read_int(entry / "compr_data_size"),
            "mem_used_total": _read_int(entry / "mem_used_total"),
            "mem_limit": _read_int(entry / "mem_limit"),
            "max_comp_streams": _read_int(entry / "max_comp_streams"),
        }

    def probe_signatures(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return self.blkid.probe(str(record.get("devnode") or ""))


def partition_probe_fields(probe: Optional[Dict[str, Any]]) -> Dict[str, str]:
    values = dict((probe or {}).get("values") or {})
    raw_type = values.get("PART_ENTRY_TYPE") or ""
    looks_uuid = bool(re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", raw_type))
    return {
        "scheme": values.get("PART_ENTRY_SCHEME") or values.get("PTTYPE") or "",
        "table_uuid": values.get("PTUUID") or "",
        "partition_number": values.get("PART_ENTRY_NUMBER") or "",
        "partition_type": raw_type,
        "partition_type_uuid": raw_type if looks_uuid else "",
        "partition_uuid": values.get("PART_ENTRY_UUID") or "",
        "partition_name": values.get("PART_ENTRY_NAME") or "",
        "partition_flags": values.get("PART_ENTRY_FLAGS") or "",
        "partition_offset": values.get("PART_ENTRY_OFFSET") or "",
        "partition_size": values.get("PART_ENTRY_SIZE") or "",
    }


def signature_probe_fields(probe: Optional[Dict[str, Any]]) -> Dict[str, str]:
    values = dict((probe or {}).get("values") or {})
    return {
        "usage": values.get("USAGE") or "",
        "type": values.get("TYPE") or "",
        "version": values.get("VERSION") or "",
        "uuid": values.get("UUID") or "",
        "label": values.get("LABEL") or "",
    }
