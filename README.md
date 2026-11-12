<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/block-devices.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/block-devices.png"
      alt="Block Devices screenshot"
      width="900"
    >
  </a>
</p>

# Block Devices

**Expose. Explore. Explain.**

Block Devices is a read-only Linux block-device topology, geometry, mapping and signature inspector. Normal inventory acquisition stays close to the kernel's sysfs block model, with deeper actions kept explicit.

Current release: **0.0.13**

Repository: <https://github.com/linspectacles/block-devices>

## What Block Devices is

Block Devices answers a focused question: **what block devices exist, how are they related, and what geometry or signatures does the kernel/device interface report?**

Block Devices draws inspiration from the storage-inspection spirit of **Microsoft Sysinternals DiskExt, DiskView, NTFSInfo and LDMDump**. It is not a port of those tools: the implemented model is Linux-native and follows sysfs block topology, geometry, mappings and explicitly requested signature information.

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- Primary inventory from `/sys/class/block` and per-device sysfs attributes.
- Partition start/end/offset/length information plus logical/physical block geometry, alignment and discard metadata where exposed.
- Explicit parent/partition, holders and slaves relationships.
- Read-only **Layout...** view using the current snapshot.
- Read-only **Mapping Details...** view for stacked block topology from the current snapshot.
- Explicit **Signatures...** selected-device probe through `libblkid`; it is never run by ordinary Refresh.
- Deeper Device Mapper and MD RAID metadata where exposed by the collected kernel interfaces.

## Data sources and acquisition

- `/sys/class/block` and per-device sysfs attributes.
- `/sys/class/block/<device>/holders` and `/sys/class/block/<device>/slaves`.
- `libblkid` only for the explicit selected-device **Signatures...** action.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Block Devices follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

Ordinary Refresh does not invoke `lsblk`, the `blkid` CLI, `udevadm`, `dmsetup`, `mdadm`, LVM tools, mount tools or SMART tools. The applet does not inspect mounted-filesystem internals, file-to-sector mappings, performance counters or perform storage administration.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Toggle Horizontal / Vertical details | `Ctrl+L` |
| Refresh block inventory | `Shift+F5` |
| Options | `Ctrl+/` |

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_block_devices/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_block_devices/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── block_devices/
    ├── applet.py
    ├── block_devices.py
    ├── _support.py
    └── icon.png
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Block Devices is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/block-devices>
- Issues: <https://github.com/linspectacles/block-devices/issues>

<p align="center">
  <a href="https://github.com/linspectacles/block-devices">
    <img
      src="block_devices/icon.png"
      alt="Block Devices"
      width="256"
    >
  </a>
</p>
