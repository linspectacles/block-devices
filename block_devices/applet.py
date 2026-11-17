#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json
import os
import re
import shutil
import subprocess

APPLET_ID = "linspectacles-block-devices"
APPLET_NAME = "Block Devices"
APPLET_VERSION = "0.0.20"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_ORGANIZATION_NAME = "LinSpectacles"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/block-devices"

from PyQt6.QtCore import QSettings, Qt, QRectF, QSize, QUrl
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QIcon,
    QKeySequence,
    QPainter,
    QPen,
    QPixmap,
    QShortcut,
    QTextCharFormat,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ._support import (
    ColumnVisibilityController,
    MetadataHighlighter,
    STANDALONE_STYLESHEET,
    apply_metadata_font,
    export_records_dialog,
    metadata_font_qss,
)
from .block_devices import (
    BlockDevicesProvider,
    CollectionResult,
    SECTOR_BYTES,
    format_bool,
    format_bytes,
    format_count,
    partition_probe_fields,
    signature_probe_fields,
)


COLUMNS = [
    ("name", "Device", 150, "left"),
    ("category", "Category", 150, "left"),
    ("major_minor", "Major:Minor", 105, "left"),
    ("size", "Size", 115, "right"),
    ("access", "Access", 105, "left"),
]

CATEGORIES = [
    "All Categories",
    "Disk",
    "Partition",
    "Device Mapper",
    "MD RAID",
    "Loop",
    "Zram",
    "Other / Virtual",
]


def _natural_key(value):
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", str(value))]


def _show_value(value, *, empty="Not reported"):
    if value is None:
        return "Unavailable"
    if value == "":
        return empty
    return str(value)


def _heading(lines, title):
    if lines and lines[-1] != "":
        lines.append("")
    lines.append(f"--- {title} ---")


def _kv(lines, key, value):
    lines.append(f"{key}: {value}")


def _ratio_percent(part, whole):
    if part is None or whole in (None, 0):
        return None
    try:
        return float(part) / float(whole) * 100.0
    except Exception:
        return None


def _metadata_lines(record, acquired_at):
    lines = []
    _heading(lines, "IDENTITY")
    _kv(lines, "Device", record.get("name", ""))
    _kv(lines, "Category", record.get("category", ""))
    _kv(lines, "Major:Minor", record.get("major_minor", "Unavailable"))
    _kv(lines, "Device Node", record.get("devnode", "Unavailable"))
    _kv(lines, "Kernel Device Path", record.get("sysfs_path", "Unavailable"))
    _kv(lines, "Size", format_bytes(record.get("size_bytes")))
    _kv(lines, "Access", record.get("access", "Unknown"))
    _kv(lines, "Read Only", format_bool(record.get("read_only")))
    _kv(lines, "Removable", format_bool(record.get("removable")))
    _kv(lines, "Rotational", format_bool(record.get("rotational")))

    hardware = [record.get(k) for k in ("vendor", "model", "revision", "serial", "wwid")]
    if any(v not in (None, "") for v in hardware):
        _heading(lines, "HARDWARE")
        _kv(lines, "Vendor", _show_value(record.get("vendor")))
        _kv(lines, "Model", _show_value(record.get("model")))
        _kv(lines, "Revision", _show_value(record.get("revision")))
        _kv(lines, "Serial", _show_value(record.get("serial")))
        _kv(lines, "WWID", _show_value(record.get("wwid")))

    _heading(lines, "GEOMETRY")
    _kv(lines, "Size", format_bytes(record.get("size_bytes")))
    _kv(lines, "Device Sectors", format_count(record.get("size_sectors")))
    _kv(lines, "Logical Block Size", format_bytes(record.get("logical_block_size")))
    _kv(lines, "Physical Block Size", format_bytes(record.get("physical_block_size")))
    _kv(lines, "Minimum I/O Size", format_bytes(record.get("minimum_io_size")))
    _kv(lines, "Optimal I/O Size", format_bytes(record.get("optimal_io_size")))
    _kv(lines, "Alignment Offset", format_bytes(record.get("alignment_offset")))
    if record.get("discard_granularity") is not None or record.get("discard_max_bytes") is not None:
        _kv(lines, "Discard Granularity", format_bytes(record.get("discard_granularity")))
        _kv(lines, "Maximum Discard Bytes", format_bytes(record.get("discard_max_bytes")))

    if record.get("partition_number") is not None:
        _heading(lines, "PARTITION")
        _kv(lines, "Partition Number", format_count(record.get("partition_number")))
        _kv(lines, "Parent Device", _show_value(record.get("parent_device")))
        _kv(lines, "Start Sector", format_count(record.get("start_sector")))
        _kv(lines, "Sector Count", format_count(record.get("sector_count")))
        _kv(lines, "End Sector", format_count(record.get("end_sector")))
        _kv(lines, "Start Offset", format_bytes(record.get("start_offset_bytes")))
        _kv(lines, "Length", format_bytes(record.get("length_bytes")))
        parent = record.get("parent_record") or {}
        parent_bytes = parent.get("size_bytes")
        parent_sectors = parent.get("size_sectors")
        _kv(lines, "Parent Size", format_bytes(parent_bytes))
        start_pct = _ratio_percent(record.get("start_sector"), parent_sectors)
        end_exclusive = None
        if record.get("start_sector") is not None and record.get("sector_count") is not None:
            end_exclusive = record.get("start_sector") + record.get("sector_count")
        end_pct = _ratio_percent(end_exclusive, parent_sectors)
        if start_pct is not None and end_pct is not None:
            _kv(lines, "Position on Parent", f"{start_pct:.2f}% – {end_pct:.2f}%")
        else:
            _kv(lines, "Position on Parent", "Unavailable")

    _heading(lines, "RELATIONSHIPS")
    _kv(lines, "Parent Device", _show_value(record.get("parent_device"), empty="None reported"))
    _kv(lines, "Partitions", ", ".join(record.get("partitions") or []) or "None reported")
    _kv(lines, "Underlying Devices", ", ".join(record.get("slaves") or []) or "None reported")
    _kv(lines, "Holding Devices", ", ".join(record.get("holders") or []) or "None reported")

    queue_fields = [record.get(k) for k in ("scheduler", "read_ahead_kb", "nr_requests", "max_sectors_kb", "write_cache", "rq_affinity", "nomerges")]
    if any(v is not None for v in queue_fields):
        _heading(lines, "QUEUE")
        _kv(lines, "Scheduler", _show_value(record.get("scheduler")))
        _kv(lines, "Read Ahead", "Unavailable" if record.get("read_ahead_kb") is None else f"{record.get('read_ahead_kb'):,} KiB")
        _kv(lines, "Requests", format_count(record.get("nr_requests")))
        _kv(lines, "Maximum Sectors", "Unavailable" if record.get("max_sectors_kb") is None else f"{record.get('max_sectors_kb'):,} KiB")
        _kv(lines, "Write Cache", _show_value(record.get("write_cache")))
        _kv(lines, "RQ Affinity", format_count(record.get("rq_affinity")))
        _kv(lines, "No Merges", format_count(record.get("nomerges")))

    dm = record.get("dm")
    if dm:
        _heading(lines, "DEVICE MAPPER")
        _kv(lines, "DM Name", _show_value(dm.get("name")))
        _kv(lines, "DM UUID", _show_value(dm.get("uuid")))
        _kv(lines, "Suspended", format_bool(dm.get("suspended")))
        _kv(lines, "Underlying Devices", ", ".join(record.get("slaves") or []) or "None reported")
        _kv(lines, "Holding Devices", ", ".join(record.get("holders") or []) or "None reported")

    md = record.get("md")
    if md:
        _heading(lines, "MD RAID")
        labels = [
            ("Level", "level", None),
            ("Array State", "array_state", None),
            ("Metadata Version", "metadata_version", None),
            ("RAID Devices", "raid_devices", "count"),
            ("Active Devices", "active_devices", "count"),
            ("Working Devices", "working_devices", "count"),
            ("Failed Devices", "failed_devices", "count"),
            ("Spare Devices", "spare_devices", "count"),
            ("Degraded Devices", "degraded_devices", "count"),
            ("Component Size", "component_size", "sectors"),
            ("Chunk Size", "chunk_size", "bytes"),
            ("Layout", "layout", None),
            ("Sync Action", "sync_action", None),
            ("Sync Completed", "sync_completed", None),
            ("Mismatch Count", "mismatch_count", "count"),
        ]
        for label, key, kind in labels:
            value = md.get(key)
            if kind == "count": value = format_count(value)
            elif kind == "bytes": value = format_bytes(value)
            elif kind == "sectors": value = "Unavailable" if value is None else f"{value:,} sectors ({format_bytes(value * SECTOR_BYTES)})"
            else: value = _show_value(value)
            _kv(lines, label, value)
        completed = str(md.get("sync_completed") or "")
        if "/" in completed:
            try:
                num, den = [int(x.strip()) for x in completed.split("/", 1)]
                _kv(lines, "Sync Progress", "Unavailable" if den == 0 else f"{num / den * 100.0:.1f}%")
            except ValueError:
                pass

    members = record.get("md_members") or []
    if members:
        _heading(lines, "MEMBERS")
        for idx, member in enumerate(members, 1):
            name = member.get("device") or f"Member {idx}"
            detail = []
            if member.get("slot") is not None: detail.append(f"slot {member['slot']}")
            if member.get("state"): detail.append(str(member["state"]))
            if member.get("offset") is not None: detail.append(f"offset {member['offset']}")
            if member.get("errors") is not None: detail.append(f"errors {member['errors']}")
            _kv(lines, name, "; ".join(detail) or "Reported member")

    loop = record.get("loop")
    if loop:
        _heading(lines, "LOOP")
        _kv(lines, "Backing File", _show_value(loop.get("backing_file")))
        _kv(lines, "Offset", format_bytes(loop.get("offset")))
        _kv(lines, "Size Limit", format_bytes(loop.get("size_limit")))
        _kv(lines, "Autoclear", format_bool(loop.get("autoclear")))
        _kv(lines, "Direct I/O", format_bool(loop.get("direct_io")))

    zram = record.get("zram")
    if zram:
        _heading(lines, "ZRAM")
        _kv(lines, "Compression Algorithm", _show_value(zram.get("algorithm")))
        _kv(lines, "Disk Size", format_bytes(zram.get("disksize")))
        _kv(lines, "Original Data", format_bytes(zram.get("orig_data_size")))
        _kv(lines, "Compressed Data", format_bytes(zram.get("compr_data_size")))
        _kv(lines, "Memory Used", format_bytes(zram.get("mem_used_total")))
        _kv(lines, "Memory Limit", format_bytes(zram.get("mem_limit")))
        _kv(lines, "Maximum Compression Streams", format_count(zram.get("max_comp_streams")))

    probe = record.get("probe")
    if probe:
        part = partition_probe_fields(probe)
        sig = signature_probe_fields(probe)
        if any(part.values()):
            _heading(lines, "PARTITION TABLE")
            _kv(lines, "Scheme", part["scheme"] or "Not reported")
            _kv(lines, "Partition Table UUID", part["table_uuid"] or "Not reported")
            _kv(lines, "Partition Number", part["partition_number"] or "Not reported")
            _kv(lines, "Partition Type", part["partition_type"] or "Not reported")
            _kv(lines, "Partition Type UUID", part["partition_type_uuid"] or "Not reported")
            _kv(lines, "Partition UUID", part["partition_uuid"] or "Not reported")
            _kv(lines, "Partition Name", part["partition_name"] or "Not reported")
            _kv(lines, "Partition Flags", part["partition_flags"] or "Not reported")
        if any(sig.values()):
            _heading(lines, "CONTENT SIGNATURE")
            _kv(lines, "Usage", sig["usage"] or "Not reported")
            _kv(lines, "Type", sig["type"] or "Not reported")
            _kv(lines, "Version", sig["version"] or "Not reported")
            _kv(lines, "UUID", sig["uuid"] or "Not reported")
            _kv(lines, "Label", sig["label"] or "Not reported")
        _kv(lines, "Probe Status", probe.get("status") or "Unknown")
    else:
        _heading(lines, "CONTENT PROBE")
        _kv(lines, "Status", "Not run — open the Signatures tab for an explicit selected-device probe")

    _heading(lines, "SOURCE")
    _kv(lines, "Primary Inventory", "/sys/class/block")
    _kv(lines, "Device Attributes", "per-device sysfs")
    _kv(lines, "Secondary Probe", "libblkid — explicit Signatures tab only")
    _kv(lines, "Acquired", acquired_at.isoformat(timespec="seconds") if acquired_at else "Unavailable")
    return lines


class LayoutBarWidget(QWidget):
    def __init__(self, parent_record, partitions, selected_name=None, parent=None):
        super().__init__(parent)
        self.parent_record = parent_record
        self.partitions = list(partitions)
        self.selected_name = selected_name
        self.setMinimumHeight(120)

    def sizeHint(self):
        return QSize(800, 130)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(18, 30, -18, -28)
        painter.setPen(QPen(QColor("#666666"), 1))
        painter.setBrush(QBrush(QColor("#252526")))
        painter.drawRect(rect)
        total = self.parent_record.get("size_sectors") or 0
        if total <= 0:
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "Layout unavailable")
            return
        palette = ["#007acc", "#4ec9b0", "#c586c0", "#dcdcaa", "#ce9178", "#9cdcfe", "#b5cea8"]
        for idx, part in enumerate(self.partitions):
            start = part.get("start_sector")
            count = part.get("sector_count")
            if start is None or count is None or count <= 0:
                continue
            x = rect.left() + rect.width() * (start / total)
            w = max(2.0, rect.width() * (count / total))
            segment = QRectF(x, rect.top(), w, rect.height())
            color = QColor("#094771") if part.get("name") == self.selected_name else QColor(palette[idx % len(palette)])
            painter.setPen(QPen(QColor("#111111"), 1))
            painter.setBrush(QBrush(color))
            painter.drawRect(segment)
            if w >= 34:
                painter.setPen(QPen(QColor("#ffffff"), 1))
                painter.drawText(segment, Qt.AlignmentFlag.AlignCenter, str(part.get("name", "")))
        painter.setPen(QPen(QColor("#dcdcdc"), 1))
        painter.drawText(18, 20, "0")
        painter.drawText(self.width() - 150, 20, f"{self.parent_record.get('size_sectors', 0):,} sectors")
        painter.drawText(18, self.height() - 6, "Uncovered ranges mean: no partition object in the current inventory.")


class LayoutDialog(QDialog):
    def __init__(self, owner, parent_record, partitions, selected_name=None):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle(f"Layout — {parent_record.get('name', '')}")
        self.resize(980, 560)
        root = QVBoxLayout(self)
        header = QLabel(
            f"<b>{parent_record.get('name','')}</b> &nbsp;·&nbsp; {parent_record.get('major_minor','')} &nbsp;·&nbsp; "
            f"{format_bytes(parent_record.get('size_bytes'))} &nbsp;·&nbsp; {format_count(parent_record.get('size_sectors'))} sectors"
        )
        root.addWidget(header)
        note = QLabel("Read-only block range map from the current sysfs snapshot. It does not show filesystem usage or file placement.")
        note.setWordWrap(True); root.addWidget(note)
        root.addWidget(LayoutBarWidget(parent_record, partitions, selected_name, self))
        table = QTableWidget(len(partitions), 6)
        table.setHorizontalHeaderLabels(["Device", "Partition", "Start Sector", "End Sector", "Size", "Major:Minor"])
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); table.verticalHeader().setVisible(False)
        for row, part in enumerate(partitions):
            vals = [
                part.get("name", ""),
                format_count(part.get("partition_number")),
                format_count(part.get("start_sector")),
                format_count(part.get("end_sector")),
                format_bytes(part.get("size_bytes")),
                part.get("major_minor", ""),
            ]
            for col, value in enumerate(vals): table.setItem(row, col, QTableWidgetItem(str(value)))
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        root.addWidget(table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(self.reject); root.addWidget(buttons)


class DeviceDetailsDialog(QDialog):
    def __init__(self, owner, selected, by_name):
        super().__init__(owner)
        self.owner = owner
        self.selected = selected
        self.by_name = by_name
        self._signatures_loaded = False
        self._signatures_privileged_active = False
        self._ordinary_probe = None
        self.setWindowTitle(f"Device Details — {selected.get('name','')}")
        self.resize(980, 680)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_mapping_tab(), "Mapping")
        self.signatures_tab = self._build_signatures_tab()
        self.signatures_index = self.tabs.addTab(self.signatures_tab, "Signatures")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(self.tabs, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _build_mapping_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        note = QLabel(
            "Read-only block topology from the current sysfs snapshot. "
            "Parent/partition relationships are kept distinct from holders/slaves relationships."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        tree = QTreeWidget()
        tree.setColumnCount(5)
        tree.setHeaderLabels(["Device", "Category", "Major:Minor", "Size", "Relationship"])
        layout.addWidget(tree, 1)

        def add_node(parent_item, record, relation, visited, direction):
            key = str(record.get("major_minor") or record.get("sysfs_path") or record.get("name"))
            repeated = key in visited
            item = QTreeWidgetItem([
                str(record.get("name", "")),
                str(record.get("category", "")),
                str(record.get("major_minor", "")),
                format_bytes(record.get("size_bytes")),
                relation + (" — already shown" if repeated else ""),
            ])
            parent_item.addChild(item)
            if repeated:
                return
            next_visited = set(visited)
            next_visited.add(key)
            names = record.get("holders") if direction == "up" else record.get("slaves")
            for name in names or []:
                target = self.by_name.get(name)
                if target:
                    add_node(
                        item,
                        target,
                        "Holding block device" if direction == "up" else "Underlying block device",
                        next_visited,
                        direction,
                    )

        above = QTreeWidgetItem(["HOLDING / ABOVE", "", "", "", ""])
        tree.addTopLevelItem(above)
        for name in self.selected.get("holders") or []:
            if name in self.by_name:
                add_node(above, self.by_name[name], "Holding block device", set(), "up")
        if above.childCount() == 0:
            above.addChild(QTreeWidgetItem(["None reported", "", "", "", ""]))

        center = QTreeWidgetItem(["SELECTED DEVICE", "", "", "", ""])
        tree.addTopLevelItem(center)
        center.addChild(QTreeWidgetItem([
            self.selected.get("name", ""),
            self.selected.get("category", ""),
            self.selected.get("major_minor", ""),
            format_bytes(self.selected.get("size_bytes")),
            "Selected block object",
        ]))

        below = QTreeWidgetItem(["UNDERLYING / BELOW", "", "", "", ""])
        tree.addTopLevelItem(below)
        for name in self.selected.get("slaves") or []:
            if name in self.by_name:
                add_node(below, self.by_name[name], "Underlying block device", set(), "down")
        if below.childCount() == 0:
            below.addChild(QTreeWidgetItem(["None reported", "", "", "", ""]))

        family = QTreeWidgetItem(["PARENT / PARTITIONS", "", "", "", ""])
        tree.addTopLevelItem(family)
        parent_name = self.selected.get("parent_device")
        if parent_name and parent_name in self.by_name:
            parent = self.by_name[parent_name]
            family.addChild(QTreeWidgetItem([
                parent.get("name", ""),
                parent.get("category", ""),
                parent.get("major_minor", ""),
                format_bytes(parent.get("size_bytes")),
                "Parent block device",
            ]))
        for name in self.selected.get("partitions") or []:
            partition = self.by_name.get(name)
            if partition:
                family.addChild(QTreeWidgetItem([
                    partition.get("name", ""),
                    partition.get("category", ""),
                    partition.get("major_minor", ""),
                    format_bytes(partition.get("size_bytes")),
                    "Partition child",
                ]))
        if family.childCount() == 0:
            family.addChild(QTreeWidgetItem(["None reported", "", "", "", ""]))

        tree.expandAll()
        for i in range(5):
            tree.resizeColumnToContents(i)
        return page

    def _build_signatures_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        note = QLabel(
            "Explicit read-only selected-device probe. Ordinary access uses libblkid; "
            "if raw-device access is restricted, one explicit privileged retry may be requested. "
            "Ordinary Refresh never performs either probe."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        self.signatures_text = QTextEdit()
        self.signatures_text.setReadOnly(True)
        self.signatures_text.setFont(self.owner._metadata_font)
        self.signatures_text.document().setDefaultFont(self.owner._metadata_font)
        self._set_signatures_palette(False)
        self._set_signatures_text(["Open this tab to probe signatures for the selected device."])
        layout.addWidget(self.signatures_text, 1)

        self.signatures_privileged_btn = QPushButton("Privileged Access...")
        self.signatures_privileged_btn.clicked.connect(self._probe_signatures_privileged)
        self.signatures_privileged_btn.setVisible(False)
        layout.addWidget(self.signatures_privileged_btn, alignment=Qt.AlignmentFlag.AlignRight)
        return page

    def _set_signatures_palette(self, privileged=False):
        if privileged:
            background = "#1e1e1e"
            foreground = "#dcdcdc"
            border = "#d6a23d"
        else:
            background = "#151719"
            foreground = "#dcdcdc"
            border = "#333333"
        self.signatures_text.setStyleSheet(
            f"QTextEdit {{ background-color: {background}; color: {foreground}; "
            f"border: 1px solid {border}; {metadata_font_qss(self.owner._metadata_font)} }}"
        )

    def _set_signatures_text(self, lines):
        self.signatures_text.clear()
        heading_fmt = QTextCharFormat()
        heading_fmt.setForeground(QColor("#f2d18b" if self._signatures_privileged_active else "#9cdcfe"))
        heading_fmt.setFontWeight(600)
        value_fmt = QTextCharFormat()
        value_fmt.setForeground(QColor("#e5bd70" if self._signatures_privileged_active else "#dcdcdc"))
        cursor = self.signatures_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for index, line in enumerate(lines):
            if line.startswith("--- ") and line.endswith(" ---"):
                cursor.insertText(line, heading_fmt)
            elif self._signatures_privileged_active and ":" in line:
                key, value = line.split(":", 1)
                cursor.insertText(f"{key}:", heading_fmt)
                cursor.insertText(value, value_fmt)
            else:
                cursor.insertText(line, value_fmt)
            if index + 1 < len(lines):
                cursor.insertText("\n", value_fmt)
        self.signatures_text.setTextCursor(cursor)

    def _on_tab_changed(self, index):
        if index != self.signatures_index:
            if self._signatures_privileged_active:
                self._collapse_privileged_signatures()
            return
        if self._signatures_loaded:
            return
        self._signatures_loaded = True
        self._signatures_privileged_active = False
        self._set_signatures_palette(False)
        self.owner.set_status(f"Probing signatures for {self.selected.get('name','')}…")
        QApplication.processEvents()
        probe = self.owner.provider.probe_signatures(self.selected)
        self._ordinary_probe = probe
        self.selected["probe"] = probe
        self.owner._show_metadata(self.selected)
        self.owner._update_status()
        self._render_signatures(probe, access="Ordinary")
        devnode = str(self.selected.get("devnode") or "")
        restricted = (
            probe.get("status") == "Could not open the selected device for read-only probing"
            and bool(devnode)
            and Path(devnode).exists()
            and not os.access(devnode, os.R_OK)
        )
        self.signatures_privileged_btn.setVisible(
            restricted
            and shutil.which("pkexec") is not None
            and shutil.which("blkid") is not None
        )

    def _collapse_privileged_signatures(self):
        self._signatures_privileged_active = False
        self._set_signatures_palette(False)
        self.signatures_privileged_btn.setVisible(False)
        if self._ordinary_probe is not None:
            self.selected["probe"] = self._ordinary_probe
            self.owner._show_metadata(self.selected)
        self._ordinary_probe = None
        self._signatures_loaded = False
        self._set_signatures_text(["Open this tab to probe signatures for the selected device."])
        self.owner._update_status()

    def _probe_signatures_privileged(self):
        pkexec = shutil.which("pkexec")
        blkid = shutil.which("blkid")
        devnode = str(self.selected.get("devnode") or "")
        if pkexec is None or blkid is None:
            probe = {
                "source": "libblkid via blkid",
                "devnode": devnode,
                "available": False,
                "status": "Privileged signature probing is unavailable because pkexec or blkid was not found",
                "values": {},
            }
            self._render_signatures(probe, access="Restricted")
            self.signatures_privileged_btn.setVisible(False)
            return

        self._signatures_privileged_active = True
        self._set_signatures_palette(True)
        self.owner.set_status(f"Probing signatures with privileged access for {self.selected.get('name','')}…")
        QApplication.processEvents()
        try:
            result = subprocess.run(
                [pkexec, blkid, "-p", "-o", "export", devnode],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            probe = {
                "source": "libblkid via blkid",
                "devnode": devnode,
                "available": True,
                "status": f"Unable to probe the selected device with privileged access: {exc}",
                "values": {},
            }
            self._render_signatures(probe, access="Privileged")
            self.owner._update_status()
            return

        if result.returncode not in {0, 2}:
            detail = (result.stderr or "Privileged signature probe was cancelled or failed.").strip()
            probe = {
                "source": "libblkid via blkid",
                "devnode": devnode,
                "available": True,
                "status": detail,
                "values": {},
            }
            self._render_signatures(probe, access="Privileged")
            self.owner._update_status()
            return

        values = {}
        for line in (result.stdout or "").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key and key != "DEVNAME":
                values[key] = value
        probe = {
            "source": "libblkid via blkid",
            "devnode": devnode,
            "available": True,
            "status": "Probe completed" if values else "No recognized signature was reported",
            "values": values,
        }
        self.selected["probe"] = probe
        self.owner._show_metadata(self.selected)
        self.owner._update_status()
        self.signatures_privileged_btn.setVisible(False)
        self._render_signatures(probe, access="Privileged")

    def _render_signatures(self, probe, access="Ordinary"):
        values = probe.get("values") or {}
        part = partition_probe_fields(probe)
        sig = signature_probe_fields(probe)
        lines = [
            "--- PROBE ---",
            f"Device: {self.selected.get('devnode','')}",
            f"Source: {probe.get('source') or 'libblkid'}",
            f"Access: {access}",
            f"Status: {probe.get('status','Unknown')}",
        ]
        if any(part.values()):
            lines += ["", "--- PARTITION TABLE ---"]
            for label, key in [
                ("Scheme", "scheme"),
                ("Partition Table UUID", "table_uuid"),
                ("Partition Number", "partition_number"),
                ("Partition Type", "partition_type"),
                ("Partition Type UUID", "partition_type_uuid"),
                ("Partition UUID", "partition_uuid"),
                ("Partition Name", "partition_name"),
                ("Partition Flags", "partition_flags"),
                ("Partition Offset", "partition_offset"),
                ("Partition Size", "partition_size"),
            ]:
                lines.append(f"{label}: {part.get(key) or 'Not reported'}")
        if any(sig.values()):
            lines += ["", "--- CONTENT SIGNATURE ---"]
            for label, key in [
                ("Usage", "usage"),
                ("Type", "type"),
                ("Version", "version"),
                ("UUID", "uuid"),
                ("Label", "label"),
            ]:
                lines.append(f"{label}: {sig.get(key) or 'Not reported'}")
        extras = {
            key: value
            for key, value in values.items()
            if key not in {
                "USAGE",
                "TYPE",
                "VERSION",
                "UUID",
                "LABEL",
                "PTTYPE",
                "PTUUID",
                "PART_ENTRY_SCHEME",
                "PART_ENTRY_NUMBER",
                "PART_ENTRY_TYPE",
                "PART_ENTRY_UUID",
                "PART_ENTRY_NAME",
                "PART_ENTRY_FLAGS",
                "PART_ENTRY_OFFSET",
                "PART_ENTRY_SIZE",
            }
        }
        if extras:
            lines += ["", "--- ADDITIONAL REPORTED VALUES ---"]
            for key in sorted(extras):
                lines.append(f"{key}: {extras[key]}")
        self._set_signatures_text(lines)


class BlockDevicesOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner); self.owner = owner
        self.setWindowTitle("Options — Block Devices"); self.resize(920, 690)
        root = QVBoxLayout(self); tabs = QTabWidget(); root.addWidget(tabs, 1)

        appearance = QWidget(); al = QVBoxLayout(appearance); al.setContentsMargins(12,12,12,12); al.setSpacing(10)
        h = QLabel("Metadata display"); f = h.font(); f.setBold(True); h.setFont(f); al.addWidget(h)
        note = QLabel("F3 shows or hides Metadata Details, Ctrl+L toggles Horizontal/Vertical, Ctrl+/ opens Options, and Shift+F5 refreshes the block inventory.")
        note.setWordWrap(True); al.addWidget(note)
        self.show_details = QCheckBox("Show Metadata Details"); self.show_details.setChecked(owner.details_panel.isVisible()); self.show_details.toggled.connect(owner.set_details_visible); al.addWidget(self.show_details)
        row = QHBoxLayout(); row.addWidget(QLabel("Record details layout:")); combo = QComboBox(); combo.addItems(["Horizontal", "Vertical"]); combo.setCurrentText("Vertical" if owner.details_orientation == "vertical" else "Horizontal"); combo.currentTextChanged.connect(lambda t: owner.set_details_orientation(t.lower(), persist=True)); row.addWidget(combo); row.addStretch(1); al.addLayout(row); al.addStretch(1); tabs.addTab(appearance, "Appearance")

        sources = QWidget(); sl = QVBoxLayout(sources); sl.setContentsMargins(12,12,12,12); sl.setSpacing(10)
        sh = QLabel("Data Sources"); sf = sh.font(); sf.setBold(True); sf.setPointSize(max(sf.pointSize(), 11)); sh.setFont(sf); sl.addWidget(sh)
        sn = QLabel("Primary inventory remains kernel/sysfs-only. libblkid is an explicit selected-device secondary probe and never runs during ordinary Refresh."); sn.setWordWrap(True); sl.addWidget(sn)
        st = QTextEdit(); st.setReadOnly(True); st.setFont(owner._metadata_font); st.document().setDefaultFont(owner._metadata_font)
        st.setStyleSheet(f"QTextEdit {{ background-color: #151719; color: #dcdcdc; border: 1px solid #333333; {metadata_font_qss(owner._metadata_font)} }}")
        heading_fmt = QTextCharFormat(); heading_fmt.setForeground(QColor("#9cdcfe")); heading_fmt.setFontWeight(600)
        value_fmt = QTextCharFormat(); value_fmt.setForeground(QColor("#dcdcdc"))
        cursor = st.textCursor(); cursor.movePosition(QTextCursor.MoveOperation.End)
        source_groups = [
            ("Primary inventory", ["/sys/class/block and per-device sysfs attributes"]),
            ("Topology", ["/sys/class/block/<device>/holders", "/sys/class/block/<device>/slaves", "resolved kernel parent/partition topology"]),
            ("Device Mapper", ["per-device sysfs dm attributes"]),
            ("MD RAID", ["per-device sysfs md attributes"]),
            ("Content / partition probe", ["libblkid, selected device only, explicit Signatures tab", "If ordinary raw-device access is restricted, the Signatures tab can request one selected-device privileged probe via pkexec and blkid -p.", "No probe is performed by Refresh. Probe results live only in the current in-memory snapshot."]),
            ("Not used by normal inspection", ["lsblk, blkid CLI, udevadm, dmsetup, mdadm, pvs/vgs/lvs, mount/findmnt, SMART tools"]),
            ("Access model", ["Read-only. No storage state is modified. Privileged access, when explicitly requested, is limited to one selected-device blkid -p probe."]),
        ]
        for group_index, (heading, lines) in enumerate(source_groups):
            if group_index:
                cursor.insertText("\n", value_fmt)
            cursor.insertText(heading + "\n", heading_fmt)
            for line in lines:
                cursor.insertText(line + "\n", value_fmt)
        st.setTextCursor(cursor)
        sl.addWidget(st, 1); tabs.addTab(sources, "Sources")

        export = QWidget(); el = QVBoxLayout(export); el.setContentsMargins(12,12,12,12); el.setSpacing(10)
        eh = QLabel("Export details"); ef = eh.font(); ef.setBold(True); eh.setFont(ef); el.addWidget(eh)
        en = QLabel("Export the currently visible Block Devices rows. Metadata Details can be included as an additional field."); en.setWordWrap(True); el.addWidget(en)
        self.export_metadata = QCheckBox("Include Metadata Details"); el.addWidget(self.export_metadata); el.addStretch(1)
        er = QHBoxLayout(); er.addStretch(1); eb = QPushButton("Export..."); eb.clicked.connect(self._export); er.addWidget(eb); el.addLayout(er); tabs.addTab(export, "Export")

        about = QWidget(); bl = QVBoxLayout(about); bl.setContentsMargins(24,20,24,18); bl.setSpacing(8)
        icon_label = QLabel(); icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter); icon_label.setFixedSize(112,112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pix = QPixmap(str(icon_path));
            if not pix.isNull(): icon_label.setPixmap(pix.scaled(112,112,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
        bl.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)
        name = QLabel("<h2 style='margin:0'>Block Devices</h2>"); name.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(name)
        ver = QLabel(f"Version {APPLET_VERSION}"); ver.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(ver)
        slogan = QLabel("<b>Expose. Explore. Explain.</b>"); slogan.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(slogan)
        desc = QLabel("A read-only LinSpectacles applet for Linux block-device geometry, topology, mappings and explicit content-signature inspection."); desc.setWordWrap(True); desc.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(desc)
        details = QLabel(
            f"<b>Build:</b> Standalone {APPLET_ORGANIZATION_NAME} applet<br>"
            f"<b>Organisation ID:</b> <a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        ); details.setWordWrap(True); details.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction | Qt.TextInteractionFlag.TextSelectableByMouse); details.setOpenExternalLinks(True); details.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(details)
        copyright_label = QLabel("Copyright © 2026 <a href='https://github.com/brunonlinespace'>brunonlinespace</a>"); copyright_label.setOpenExternalLinks(True); copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(copyright_label)
        license_label = QLabel("Licensed under GNU GPLv3 or later."); license_label.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(license_label)
        readme_url = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "README.md")).toString()
        license_url = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        ); links.setOpenExternalLinks(True); links.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(links)
        bl.addStretch(1); tabs.addTab(about, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(self.reject); root.addWidget(buttons)

    def _export(self):
        self.owner.export_current_data(include_metadata=self.export_metadata.isChecked())


class BlockDevicesTab(QWidget):
    def __init__(self, parent=None, provider=None):
        super().__init__(parent)
        self.provider = provider or BlockDevicesProvider()
        self.settings = QSettings("brunonlinespace", "Block Devices")
        self.snapshot = []
        self._visible_records = []
        self.warnings = []
        self.acquired_at = None
        self.details_orientation = str(self.settings.value("details_orientation", "horizontal") or "horizontal")
        if self.details_orientation not in {"horizontal", "vertical"}: self.details_orientation = "horizontal"
        self.details_visible = str(self.settings.value("details_visible", "true")).lower() not in {"false","0"}
        self.sort_column = str(self.settings.value("sort_column", "name") or "name")
        self.sort_desc = str(self.settings.value("sort_desc", "false")).lower() in {"true","1"}
        self._metadata_font = None
        self._column_callback = None
        self._configuring = False
        self._text_bg = "#1e1e1e"; self._text_fg = "#dcdcdc"; self._key_color = QColor("#4ec9b0"); self._value_color = QColor("#ce9178"); self._heading_color = QColor("#dcdcdc")
        self._setup_ui(); self._setup_shortcuts(); self._restore_persistence(); self.refresh_devices(initial=True)

    def _setup_ui(self):
        root = QVBoxLayout(self); root.setContentsMargins(12,12,12,12); root.setSpacing(10)
        top = QHBoxLayout(); self.stats_label = QLabel("Total Block Devices: 0"); f=self.stats_label.font(); f.setBold(True); f.setPointSize(max(f.pointSize(),11)); self.stats_label.setFont(f); top.addWidget(self.stats_label); top.addStretch(1)
        self.layout_btn = QPushButton("Layout..."); self.layout_btn.clicked.connect(self.show_layout); top.addWidget(self.layout_btn)
        self.device_details_btn = QPushButton("Device Details..."); self.device_details_btn.clicked.connect(self.show_device_details); top.addWidget(self.device_details_btn)
        self.refresh_btn = QPushButton("Refresh"); self.refresh_btn.clicked.connect(self.refresh_devices); top.addWidget(self.refresh_btn)
        self.options_btn = QPushButton("Options..."); self.options_btn.clicked.connect(self.show_options); top.addWidget(self.options_btn)
        root.addLayout(top)

        fl = QHBoxLayout(); ql=QLabel("Search:"); ql.setStyleSheet("font-weight: 600;"); fl.addWidget(ql)
        self.search = QLineEdit(); self.search.setPlaceholderText("Search block devices..."); self.search.setMaximumWidth(300); self.search.textChanged.connect(self._render); fl.addWidget(self.search)
        cl=QLabel("Category:"); cl.setStyleSheet("font-weight: 600;"); fl.addWidget(cl)
        self.category = QComboBox(); self.category.addItems(CATEGORIES); self.category.setMinimumWidth(180); self.category.currentTextChanged.connect(self._render); fl.addWidget(self.category)
        self.filter_status = QLabel(""); it=self.filter_status.font(); it.setItalic(True); self.filter_status.setFont(it); fl.addWidget(self.filter_status); fl.addStretch(1); root.addLayout(fl)

        self.splitter = QSplitter(Qt.Orientation.Horizontal); root.addWidget(self.splitter,1)
        self.table = QTableWidget(0,len(COLUMNS)); self.table.setHorizontalHeaderLabels([c[1] for c in COLUMNS]); self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection); self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.table.setAlternatingRowColors(True); self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_selection_changed); self.table.horizontalHeader().sectionClicked.connect(self._header_clicked); self.table.horizontalHeader().sectionResized.connect(self._save_widths); self.splitter.addWidget(self.table)
        self.column_visibility = ColumnVisibilityController(self.table, COLUMNS, self.set_status); self.column_visibility.set_changed_callback(self._hidden_changed)

        self.details_panel=QWidget(); dl=QVBoxLayout(self.details_panel); dl.setContentsMargins(8,0,0,0); dh=QLabel("Metadata Details"); df=dh.font(); df.setBold(True); df.setPointSize(max(df.pointSize(),11)); dh.setFont(df); dl.addWidget(dh)
        self.info=QTextEdit(); self.info.setReadOnly(True); self.info.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth); self._metadata_font=apply_metadata_font(self.info); self.highlighter=MetadataHighlighter(self.info.document()); dl.addWidget(self.info,1); self.splitter.addWidget(self.details_panel); self.splitter.splitterMoved.connect(lambda *_: self._save_splitter()); self._update_info_style()
        self.status=QLabel("Ready."); sf=self.status.font(); sf.setItalic(True); self.status.setFont(sf); self.status.setContentsMargins(4,4,4,4); root.addWidget(self.status)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("F3"), self, activated=self.toggle_details)
        QShortcut(QKeySequence("F4"), self, activated=self.show_device_details)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.toggle_orientation)
        QShortcut(QKeySequence("Ctrl+/"), self, activated=self.show_options)
        QShortcut(QKeySequence("Shift+F5"), self, activated=self.refresh_devices)

    def _restore_persistence(self):
        self.set_details_orientation(self.details_orientation, persist=False)
        self.set_details_visible(self.details_visible, persist=False)
        widths = self.settings.value("column_widths")
        for i, col in enumerate(COLUMNS):
            width = col[2]
            if isinstance(widths, list) and i < len(widths):
                try: width=int(widths[i])
                except Exception: pass
            self.table.setColumnWidth(i,width)
        hidden=self.settings.value("hidden_columns",[])
        if isinstance(hidden,str): hidden=[hidden] if hidden else []
        self.column_visibility.apply_hidden(hidden or [])
        sizes=self.settings.value(f"splitter/{self.details_orientation}")
        if isinstance(sizes,list) and len(sizes)==2:
            try:self.splitter.setSizes([int(sizes[0]),int(sizes[1])])
            except Exception:self.splitter.setSizes([650,520])
        else:self.splitter.setSizes([650,520])

    def _save_widths(self,*_):
        if not self._configuring: self.settings.setValue("column_widths",[self.table.columnWidth(i) for i in range(self.table.columnCount())])
    def _hidden_changed(self,hidden):
        self.settings.setValue("hidden_columns",list(hidden))
        if callable(self._column_callback):
            try:self._column_callback(list(hidden))
            except Exception:pass
    def _save_splitter(self): self.settings.setValue(f"splitter/{self.details_orientation}",self.splitter.sizes())

    def _sort_key(self,record,column):
        if column=="name":return _natural_key(record.get("name",""))
        if column=="size":return record.get("size_bytes") if record.get("size_bytes") is not None else -1
        if column=="major_minor":
            return (record.get("major") if record.get("major") is not None else -1,record.get("minor") if record.get("minor") is not None else -1)
        return str(record.get(column,"")).lower()
    def _header_clicked(self,section):
        if not 0<=section<len(COLUMNS):return
        col=COLUMNS[section][0]
        if col==self.sort_column:self.sort_desc=not self.sort_desc
        else:self.sort_column=col;self.sort_desc=False
        self.settings.setValue("sort_column",self.sort_column);self.settings.setValue("sort_desc",self.sort_desc);self._render()

    def _filtered(self):
        query=self.search.text().strip().lower(); cat=self.category.currentText(); result=[]
        for record in self.snapshot:
            if cat!="All Categories" and record.get("category")!=cat:continue
            if query:
                values=[record.get("name"),record.get("category"),record.get("major_minor"),record.get("access"),record.get("vendor"),record.get("model"),record.get("serial"),record.get("wwid"),record.get("parent_device")," ".join(record.get("holders") or [])," ".join(record.get("slaves") or [])]
                if query not in " ".join(str(v or "") for v in values).lower():continue
            result.append(record)
        try:result.sort(key=lambda r:self._sort_key(r,self.sort_column),reverse=self.sort_desc)
        except Exception:pass
        return result

    def _render(self):
        selected=self.current_record(); selected_key=selected.get("key") if selected else None
        visible=self._filtered(); self._visible_records=visible
        self.table.blockSignals(True); self.table.setRowCount(len(visible)); target=-1
        for row,record in enumerate(visible):
            if record.get("key")==selected_key:target=row
            values=[record.get("name",""),record.get("category",""),record.get("major_minor",""),record.get("size",""),record.get("access","")]
            for col,value in enumerate(values):
                item=QTableWidgetItem(str(value));
                if col==0:item.setData(Qt.ItemDataRole.UserRole,record)
                if col==3:item.setTextAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(row,col,item)
        self.table.blockSignals(False)
        if visible:
            if target<0:target=0
            self.table.setCurrentCell(target,0);self.table.selectRow(target);self._show_metadata(visible[target])
        else:
            self.table.clearSelection();self.info.clear()
        self.stats_label.setText(f"Total Block Devices: {len(self.snapshot)}")
        if len(visible)!=len(self.snapshot):self.filter_status.setText(f"Showing {len(visible)} of {len(self.snapshot)}")
        else:self.filter_status.clear()
        self._update_actions();self._update_status()

    def _update_status(self):
        base=f"{len(self._visible_records)} block device{'s' if len(self._visible_records)!=1 else ''}"
        if len(self._visible_records)!=len(self.snapshot):base=f"{len(self._visible_records)} of {len(self.snapshot)} block devices"
        if self.warnings:base+=f" — {len(self.warnings)} source note{'s' if len(self.warnings)!=1 else ''}"
        self.set_status(base)

    def current_record(self):
        row=self.table.currentRow()
        if row<0:return None
        item=self.table.item(row,0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None
    def _on_selection_changed(self):
        if self.table.signalsBlocked():return
        record=self.current_record()
        if record:self._show_metadata(record)
        else:self.info.clear()
        self._update_actions()
    def clear_info(self):
        self.info.clear()

    def append_info(self, text, style="value"):
        cursor = self.info.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(str(text))
        self.info.setTextCursor(cursor)

    def _show_metadata(self,record):
        self.clear_info()
        self.append_info("\n".join(_metadata_lines(record,self.acquired_at)))

    def _update_actions(self):
        r=self.current_record(); available=bool(r)
        # Unavailable specialist actions are hidden rather than shown disabled.
        self.device_details_btn.setVisible(available)
        layout=False
        if r:
            layout=bool(r.get("partitions") or r.get("parent_device"))
        self.layout_btn.setVisible(layout)

    def refresh_devices(self,initial=False):
        self.set_status("Refreshing block devices…"); QApplication.processEvents()
        try:result=self.provider.list_devices()
        except Exception as exc:
            if initial:self.snapshot=[]
            QMessageBox.warning(self,APPLET_NAME,f"Could not refresh block devices:\n\n{exc}");self.set_status("Block device inventory could not be read.");self._render();return
        # Parent records are snapshot relationships, not independent second-source data.
        by_name={r.get("name"):r for r in result.records}
        for r in result.records:r["parent_record"]=by_name.get(r.get("parent_device"))
        self.snapshot=list(result.records);self.warnings=list(result.warnings);self.acquired_at=datetime.now().astimezone();self._render()

    def show_layout(self):
        record=self.current_record()
        if not record:return
        by_name={r.get("name"):r for r in self.snapshot}
        if record.get("parent_device") and record.get("parent_device") in by_name:
            parent=by_name[record.get("parent_device")];selected_name=record.get("name")
        else:parent=record;selected_name=None
        parts=[r for r in self.snapshot if r.get("parent_device")==parent.get("name") and r.get("start_sector") is not None]
        parts.sort(key=lambda r:(r.get("start_sector") if r.get("start_sector") is not None else 0,_natural_key(r.get("name",""))))
        if not parts:
            QMessageBox.information(self,"Layout","No partition objects with positional geometry are present in the current snapshot.");return
        LayoutDialog(self,parent,parts,selected_name).exec()

    def show_device_details(self):
        record=self.current_record()
        if not record:return
        by_name={r.get("name"):r for r in self.snapshot}
        DeviceDetailsDialog(self,record,by_name).exec()

    def show_options(self):BlockDevicesOptionsDialog(self).exec()
    def set_status(self,text):self.status.setText(str(text))
    def toggle_details(self):self.set_details_visible(not self.details_panel.isVisible())
    def set_details_visible(self,visible,persist=True):
        self.details_visible=bool(visible);self.details_panel.setVisible(self.details_visible)
        if persist:self.settings.setValue("details_visible",self.details_visible)
    def toggle_orientation(self):self.set_details_orientation("vertical" if self.details_orientation=="horizontal" else "horizontal",persist=True)
    def set_details_orientation(self,orientation,persist=True):
        orientation=str(orientation).lower()
        if orientation not in {"horizontal","vertical"}:return
        if hasattr(self,"splitter") and self.details_orientation!=orientation:self._save_splitter()
        self.details_orientation=orientation
        if hasattr(self,"splitter"):
            details_panel=self.splitter.widget(1)
            details_layout=details_panel.layout() if details_panel is not None else None
            if orientation=="vertical":
                self.splitter.setOrientation(Qt.Orientation.Vertical)
                if details_layout is not None:details_layout.setContentsMargins(0,8,0,0)
            else:
                self.splitter.setOrientation(Qt.Orientation.Horizontal)
                if details_layout is not None:details_layout.setContentsMargins(8,0,0,0)
            sizes=self.settings.value(f"splitter/{orientation}")
            if isinstance(sizes,list) and len(sizes)==2:
                try:self.splitter.setSizes([int(sizes[0]),int(sizes[1])])
                except Exception:self.splitter.setSizes([650,520])
            else:self.splitter.setSizes([650,520])
        if persist:self.settings.setValue("details_orientation",orientation)
    def _update_info_style(self):
        self.info.setStyleSheet("QTextEdit { "+f"background: {self._text_bg}; color: {self._text_fg}; border: 1px solid #666; {metadata_font_qss(self._metadata_font)} " + "}");self.highlighter.set_colors(self._key_color,self._value_color,self._heading_color)
    def apply_host_settings(self,settings=None,column_visibility_callback=None):
        settings=settings or {};self._metadata_font=apply_metadata_font(self.info,settings.get("metadata_font",""));self._update_info_style();self._column_callback=column_visibility_callback
        hidden=settings.get("hidden_columns")
        if hidden is not None:self.column_visibility.apply_hidden(hidden)
    def set_theme_colors(self,text_bg,text_fg,key_fg,value_fg,status_bg,status_fg):
        self._text_bg=text_bg;self._text_fg=text_fg;self._key_color=QColor(key_fg);self._value_color=QColor(value_fg);self._heading_color=QColor(text_fg);self._update_info_style();self.status.setStyleSheet(f"QLabel {{ background: {status_bg}; color: {status_fg}; padding: 4px; }}")
    def get_export_records(self):return list(self._visible_records)
    def export_current_data(self,include_metadata=False):
        records=[]
        for r in self._visible_records:
            item=dict(r)
            # Remove internal non-scalar graph/cache helpers from base export.
            for k in ("related_records","parent_record"):
                item.pop(k,None)
            if include_metadata:item["metadata_details"]="\n".join(_metadata_lines(r,self.acquired_at))
            records.append(item)
        if not records:
            QMessageBox.information(self,"Export","There are no visible records to export.");return
        columns=list(COLUMNS)
        if include_metadata:columns.append(("metadata_details","Metadata Details",520,"left"))
        path=export_records_dialog(self,APPLET_NAME,records,columns=columns)
        if path is not None:self.set_status(f"Exported data to {path}")


def create_applet(parent=None):
    return BlockDevicesTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtWidgets import QMainWindow
    app=QApplication(sys.argv);app.setApplicationName(APPLET_NAME);app.setApplicationVersion(APPLET_VERSION);app.setOrganizationName(APPLET_ORGANIZATION_ID)
    icon_path=Path(__file__).resolve().parent/"icon.png"
    if icon_path.is_file():app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window=QMainWindow();window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet");window.resize(1280,820)
    if icon_path.is_file():window.setWindowIcon(QIcon(str(icon_path)))
    window.setCentralWidget(create_applet());window.show();return app.exec()
