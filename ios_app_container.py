#!/usr/bin/env python3
"""
Extract one iPhone app's data over USB (app container: Documents, Library, ...;
with a backup also its App Group and extension containers), including apps that
do NOT enable File Sharing.

How the data is fetched (first that works wins; --force-backup goes straight to 3):
  1. Direct container copy (seconds, no backup): iOS vends the whole container
     over AFC (house_arrest VendContainer) for development-signed and TestFlight
     builds. Gets EVERYTHING in the container, incl. Library/Caches and tmp, but
     not App Group containers. App Store builds are refused.
  2. File Sharing apps (UIFileSharingEnabled): Documents/ only, over AFC.
  3. Backup (any app, incl. App Store builds) through the iTunes/Finder backup
     protocol, then only the app's files are extracted. Gets what iOS puts in a
     backup, App Group / extension containers included, but NOT Library/Caches,
     tmp or files the app marks "exclude from backup".
-l lists the apps with their signing (AppStore / TestFlight / Dev); -ld only the
Dev/TestFlight ones, i.e. those that 1 usually handles.

Backup engines (--engine; default: env IOS_APP_EXTRACT_ENGINE, else finder):
  finder  Apple's own engine (AppleMobileBackup, same as Finder) into
          ~/Library/Application Support/MobileSync/Backup. Keeps the whole device
          backup (~ used iPhone storage), so after the first run iOS only sends
          changes. --finder is accepted as an alias (old commands).
  pmd3    pymobiledevice3 mobilebackup2. iOS still streams the whole device, but
          only the app's files are written, to a small per-app cache in
          ~/iOSAppBackups/cache/<bundleID>/ (next run incremental). Useful when the
          Mac has no room for a full backup. --full, --no-filter, --backup-dir and
          --clean apply to this engine only.
Even an incremental backup takes minutes: iOS scans the whole device each time.

Encrypted backups: the backup password (input hidden, or env IOS_BACKUP_PASSWORD)
is asked while the backup runs, checked against the previous backup's keybag, and
the derived key is reused to decrypt, so it adds no time.

Storage: everything lives under ~/iOSAppBackups (override with env
IOS_APP_EXTRACT_HOME). It is outside ~/Desktop and ~/Documents on purpose,
because those folders may be synced to iCloud Drive.

Usage:
    ios-app-container com.example.app
    ios-app-container "Example App" -o ~/Desktop/example_data
    ios-app-container -l                # list user apps on the device (same as --list)
    ios-app-container -ld               # only Dev/TestFlight apps (direct copy, no backup)
    ios-app-container -d                # connected iPhones (UDID, USB / Wi-Fi)
    ios-app-container -bk               # Finder backups on this Mac (--delete-backup to remove)
    ios-app-container -imazing          # iMazing backup folders, backups and known devices
    ios-app-container com.example.app --engine pmd3 --verbose   # pmd3: every file + heartbeat

Install (macOS only). Library versions are pinned in pyproject.toml because the tool uses
some internals of them; it warns at start when the installed ones differ:
    uv tool install ios-app-container
"""
import os
import sys

try:
    import pymobiledevice3  # noqa: F401
    import iphone_backup_decrypt  # noqa: F401
except ImportError:
    sys.exit("Missing pymobiledevice3 / iphone_backup_decrypt. Install the tool with: uv tool install ios-app-container")

import argparse
import asyncio
import contextlib
import getpass
import importlib.metadata
import logging
import plistlib
import shutil
import signal
import subprocess
import sqlite3
import termios
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from iphone_backup_decrypt import EncryptedBackup
from iphone_backup_decrypt import utils as backup_utils
from iphone_backup_decrypt.utils import BackupKeyBag
from pymobiledevice3.exceptions import (DeviceNotFoundError, MissingValueError, NoDeviceConnectedError,
                                        PyMobileDevice3Exception)
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services import device_link as device_link_mod
from pymobiledevice3.services.mobilebackup2 import BackupFile, Mobilebackup2Service
from pymobiledevice3.usbmux import list_devices

MAX_PASSWORD_TRIES = 3
# Versions this script was tested with. It relies on some library internals (DeviceLink._recvall,
# the "(Ignoring) ..." warning of AfcService.pull, BackupKeyBag), which may change between releases.
TESTED_VERSIONS = {"pymobiledevice3": "11.26.0", "iphone_backup_decrypt": "0.11.2"}
APPLE_MOBILE_BACKUP = ("/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/"
                       "AppleMobileDeviceHelper.app/Contents/Resources/AppleMobileBackup")
FINDER_BACKUP_ROOT = Path("~/Library/Application Support/MobileSync/Backup").expanduser()
ENGINES = ("finder", "pmd3")
ENGINE_ENV = "IOS_APP_EXTRACT_ENGINE"
IMAZING_ROOT = Path("~/Library/Application Support/iMazing").expanduser()
BASE_DIR = Path(os.environ.get("IOS_APP_EXTRACT_HOME", "~/iOSAppBackups")).expanduser()
CACHE_ROOT = BASE_DIR / "cache"
OUTPUT_ROOT = BASE_DIR / "output"
HEARTBEAT_SECONDS = 10
# Wi-Fi sync devices drop out of usbmux while the iPhone is locked/asleep: retry this long
CONNECT_RETRY_SECONDS = 20
# How often the Finder-mode progress measures the backup folder with du (walks 100k+ files)
DU_SECONDS_FULL = 30
DU_SECONDS_INCREMENTAL = 60
TASKPOLICY = "/usr/sbin/taskpolicy"
# Set while the backup password is being typed: progress lines are held back meanwhile
PROMPTING = threading.Event()
# Bump when make_filter() changes: a cache built by an older filter misses app files,
# so it must be refreshed with a full backup (incremental would not resend them).
FILTER_VERSION = "2"
FILTER_MARKER = ".filter_version"


def clear_line():
    """Erase a "\\r [progress] ..." line still on screen, so the next output starts clean."""
    return "\r\033[K" if sys.stdout.isatty() else ""


def log(msg):
    print(f"{clear_line()}[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def _pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    # OpenSSL via cryptography: ~1s for the backup keybag's 10M rounds vs ~5s with pycryptodome
    algo = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}[hash_name]()
    return PBKDF2HMAC(algo, dklen or algo.digest_size, salt, iterations).derive(password)


backup_utils.pbkdf2_hmac = _pbkdf2_hmac


async def in_daemon_thread(fn, *args):
    """Run a blocking call (password prompt) without blocking the event loop.

    Unlike asyncio.to_thread, a daemon thread does not keep the process alive after Ctrl-C.
    """
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def settle(result, exc):
        if fut.done():
            return
        if exc:
            fut.set_exception(exc)
        else:
            fut.set_result(result)

    def run():
        try:
            result, exc = fn(*args), None
        except BaseException as e:  # SystemExit from a wrong password must reach the caller
            result, exc = None, e
        try:
            loop.call_soon_threadsafe(settle, result, exc)
        except RuntimeError:  # loop already closed
            pass

    threading.Thread(target=run, daemon=True).start()
    return await fut


# ---------------------------------------------------------------- device side
async def describe_devices():
    """Connected devices, one row per UDID (USB and Wi-Fi of the same iPhone are merged)."""
    kinds = {}
    for d in await list_devices():
        kinds.setdefault(d.serial, set()).add("Wi-Fi" if d.connection_type == "Network" else d.connection_type)
    rows = []
    for udid, conn in kinds.items():
        row = {"udid": udid, "conn": "+".join(sorted(conn, key=lambda k: k != "USB")),
               "name": "?", "model": "?", "type": "?", "ios": "?"}
        try:  # a locked / untrusted device may refuse: keep "?"
            ld = await create_using_usbmux(serial=udid)
            row.update(name=clean_text(ld.all_values.get("DeviceName")) or "?", model=clean_text(ld.display_name),
                       type=str(ld.product_type), ios=str(ld.product_version))
            await ld.close()
        except Exception:
            pass
        rows.append(row)
    return rows


async def print_devices():
    rows = await describe_devices()
    if not rows:
        print("No iPhone connected (USB, or Wi-Fi sync with the iPhone unlocked on the same network)")
        return
    print_table(("UDID", "NAME", "MODEL", "TYPE", "iOS", "CONNECTION"),
                [(r["udid"], r["name"][:30], r["model"], r["type"], r["ios"], r["conn"]) for r in rows])
    print(f"\n{len(rows)} device(s). Pick one with --udid <UDID>")


async def choose_device():
    """UDID to use when no --udid was given: the only device, or ask when there are several."""
    serials = list(dict.fromkeys(d.serial for d in await list_devices()))
    if len(serials) <= 1:
        return None  # 0 or 1 device: let create_using_usbmux pick / report it
    rows = await describe_devices()
    if not sys.stdin.isatty():
        sys.exit("Several iPhones connected, pick one with --udid: "
                 + ", ".join(f"{r['udid']} ({r['name']}, {r['conn']})" for r in rows))
    print("Several iPhones connected:")
    for idx, r in enumerate(rows, 1):
        print(f"  {idx}. {r['name']} - {r['model']}, iOS {r['ios']}, {r['conn']}  ({r['udid']})")
    choice = input("Choose number: ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(rows):
        sys.exit("Invalid choice.")
    return rows[int(choice) - 1]["udid"]


async def connect_device(udid=None):
    """Lockdown client for the device, waiting a bit for one that is not visible (yet).

    Without udid and with several devices connected, asks which one (no silent pick).
    A Wi-Fi sync iPhone disappears from usbmux while it is locked or asleep and comes back
    once unlocked, so a missing device is retried for CONNECT_RETRY_SECONDS before giving up.
    """
    if udid is None:
        udid = await choose_device()
    deadline = time.time() + CONNECT_RETRY_SECONDS
    warned = False
    while True:
        try:
            return await create_using_usbmux(serial=udid)
        except (DeviceNotFoundError, NoDeviceConnectedError):
            if time.time() >= deadline:
                break
            if not warned:
                log(f"{'Device ' + udid if udid else 'No device'} not visible yet. Unlock the iPhone "
                    f"(over Wi-Fi it drops out while locked/asleep) or plug the cable; retrying "
                    f"for {CONNECT_RETRY_SECONDS}s...")
                warned = True
            await asyncio.sleep(2)
    try:
        visible = [f"{d.serial} ({'Wi-Fi' if d.connection_type == 'Network' else d.connection_type})"
                   for d in await list_devices()]
    except Exception:
        visible = []
    sys.exit(f"{'Device ' + udid if udid else 'No iPhone'} not found. Visible now: "
             f"{', '.join(visible) or 'none'}. Unlock the iPhone and keep it on the same Wi-Fi, or use the cable.")


def connection_text(lockdown) -> str:
    """" via USB" / " via Wi-Fi" (Finder's Wi-Fi sync); pymobiledevice3 prefers USB when both exist."""
    kind = getattr(getattr(lockdown.service, "mux_device", None), "connection_type", None)
    return {"USB": " via USB", "Network": " via Wi-Fi"}.get(kind, f" via {kind}" if kind else "")


async def get_user_apps(lockdown):
    async with InstallationProxyService(lockdown) as ip:
        return await ip.get_apps(application_type="User")


def resolve_app(apps, query):
    """Match by exact bundle ID, then exact app name, then partial name/bundle ID."""
    if query in apps:
        return query
    q = query.lower()

    def names(info):
        return {clean_text(info.get(k)).lower() for k in ("CFBundleDisplayName", "CFBundleName")} - {""}

    exact = [b for b, i in apps.items() if q in names(i) or b.lower() == q]
    if len(exact) == 1:
        return exact[0]
    partial = exact or [b for b, i in apps.items() if q in b.lower() or any(q in n for n in names(i))]
    if not partial:
        sys.exit(f"No app matches '{query}'. Use --list to see installed apps.")
    if len(partial) == 1:
        return partial[0]
    print(f"Multiple apps match '{query}':")
    for idx, b in enumerate(sorted(partial), 1):
        print(f"  {idx}. {apps[b].get('CFBundleDisplayName') or apps[b].get('CFBundleName')}  ({b})")
    choice = input("Choose number: ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(partial):
        sys.exit("Invalid choice.")
    return sorted(partial)[int(choice) - 1]


def clean_text(value):
    """Info.plist string without invisible format chars (e.g. U+200E in "WhatsApp") and padding."""
    return "".join(c for c in str(value or "") if unicodedata.category(c) != "Cf").strip()


def signing_kind(info):
    """AppStore / TestFlight / Dev from the signer; Dev and TestFlight builds allow VendContainer."""
    signer = str(info.get("SignerIdentity", ""))
    if "TestFlight" in signer:
        return "TestFlight"
    if signer.startswith(("Apple Development", "iPhone Developer")) or (info.get("Entitlements") or {}).get("get-task-allow"):
        return "Dev"
    if signer == "Apple iPhone OS Application Signing":
        return "AppStore"
    return signer or "?"


DIRECT_KINDS = ("Dev", "TestFlight")


def print_app_list(apps, direct_only=False):
    rows = sorted(((clean_text(i.get("CFBundleDisplayName") or i.get("CFBundleName")), b,
                    clean_text(i.get("CFBundleShortVersionString")), signing_kind(i),
                    "yes" if i.get("UIFileSharingEnabled") else "")
                   for b, i in apps.items()), key=lambda r: r[0].casefold())
    total = len(rows)
    if direct_only:
        rows = [r for r in rows if r[3] in DIRECT_KINDS]
    header = ("NAME", "BUNDLE ID", "VERSION", "SIGNING", "FILESHARING")
    widths = [min(max(len(r[c]) for r in rows + [header]), 40) for c in range(4)]
    for r in [header] + rows:
        print("  ".join(f"{r[c][:widths[c]]:{widths[c]}}" for c in range(4)) + f"  {r[4]}")
    direct = sum(r[3] in DIRECT_KINDS for r in rows)
    print(f"\n{total} user apps; {direct} Dev/TestFlight (container can usually be copied directly, no backup)")


def container_keys(info, bundle_id):
    """Strings identifying the app's files in device paths: container UUIDs, bundle ID, group IDs.

    Matched as substrings, because iOS backs up from a snapshot and the device path may
    carry a prefix (e.g. a .backup snapshot mount) before /var/mobile/Containers/...
    """
    paths = [info.get("Container")] + list((info.get("GroupContainers") or {}).values())
    keys = {f"/{Path(p).name}/" for p in filter(None, paths)}  # "/<UUID>/"
    keys.add(bundle_id)
    keys.update((info.get("GroupContainers") or {}).keys())
    return tuple(keys)


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


class Stats:
    """Transfer counters, fed by the filter callback and a patched DeviceLink._recvall."""

    def __init__(self, verbose, names_log: Path):
        self.verbose = verbose
        self.names_fd = open(names_log, "w")
        self.seen = self.kept = self.rx = 0
        self.last = ""
        self.start = time.time()

    def install_byte_counter(self):
        orig = getattr(device_link_mod.DeviceLink, "_recvall", None)
        if orig is None:  # pymobiledevice3 internals changed: backup still works, only "received" stays 0
            log("NOTE: this pymobiledevice3 version has no DeviceLink._recvall -> received bytes not counted")
            return
        stats = self

        async def counting_recvall(dl, size):
            data = await orig(dl, size)
            stats.rx += len(data)
            return data

        device_link_mod.DeviceLink._recvall = counting_recvall

    def wrap(self, filter_cb):
        def _wrapped(f: BackupFile) -> bool:
            keep = True if filter_cb is None else filter_cb(f)
            if f.device_name is not None:
                self.seen += 1
                self.kept += keep
                self.last = f.device_name
                self.names_fd.write(f"{'KEEP' if keep else 'skip'}\t{f.device_name}\n")
                if self.verbose and not PROMPTING.is_set():
                    print(f"\r    {'KEEP' if keep else 'skip'} {f.device_name}", flush=True)
            return keep
        return _wrapped

    def line(self):
        el = time.time() - self.start
        return (f"elapsed {el:4.0f}s | received {human(self.rx)} ({human(self.rx / max(el, 1))}/s) | "
                f"files {self.seen} seen, {self.kept} kept")


def make_filter(info, bundle_id):
    keys = container_keys(info, bundle_id)
    group_ids = list((info.get("GroupContainers") or {}).keys())
    domains = [f"AppDomain-{bundle_id}", f"AppDomainPlugin-{bundle_id}."] + [f"AppDomainGroup-{g}" for g in group_ids]

    def _filter(f: BackupFile) -> bool:
        if f.device_name is not None:
            dn = f.device_name + "/"
            return any(k in dn for k in keys)
        if f.domain is not None:
            return f.domain.startswith(tuple(domains))
        return False

    return _filter


async def do_backup(lockdown, backup_dir: Path, filter_cb, full, verbose):
    names_log = backup_dir / "device_files.log"
    stats = Stats(verbose, names_log)
    stats.install_byte_counter()
    pct = [0.0]

    def progress(p):
        pct[0] = p
        if not verbose and not PROMPTING.is_set():
            print(f"\r    backup progress: {p:5.1f}% | {stats.line()}   ", end="", flush=True)

    async def heartbeat():
        # Keeps printing even while the device is silent (e.g. waiting for passcode / preparing)
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            if PROMPTING.is_set():
                continue
            if verbose:
                print(f"    [heartbeat] {pct[0]:5.1f}% | {stats.line()} | last: {stats.last[-80:]}", flush=True)
            else:
                progress(pct[0])

    hb = asyncio.create_task(heartbeat())
    try:
        async with Mobilebackup2Service(lockdown) as mb:
            await mb.backup(full=full, backup_directory=backup_dir, progress_callback=progress,
                            filter_callback=stats.wrap(filter_cb))
    finally:
        hb.cancel()
        stats.names_fd.close()
    print()
    log(f"Transfer summary: {stats.line()}")
    log(f"Device file list (KEEP/skip): {names_log}")
    if filter_cb is not None and stats.kept <= 2:
        log(f"WARNING: only {stats.kept} file(s) kept by the filter. Check {names_log} "
            "to see how the app's files are named, or rerun with --no-filter.")
    return stats


def dir_size(path: Path, background=True) -> int:
    """Disk usage of a folder in bytes (du is much faster than walking 100k+ files in Python).

    background: low I/O priority, so it does not slow down a backup writing there.
    """
    cmd = ["du", "-sk", str(path)]
    if background and os.path.exists(TASKPOLICY):
        cmd = [TASKPOLICY, "-b"] + cmd
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
        return int(out.split()[0]) * 1024
    except (ValueError, IndexError):
        return 0


async def finder_backup(udid, device_dir: Path, expected_bytes, first_run):
    """Run Apple's backup engine (same as Finder).

    AppleMobileBackup prints no progress, so progress is estimated from the growth of the
    backup folder: % of the iPhone's used storage on a first full backup, written bytes
    on an incremental one (its total size is unknown in advance). The folder is measured
    only every DU_SECONDS_* (du walks the whole backup); elapsed time updates every heartbeat.
    """
    if not os.path.exists(APPLE_MOBILE_BACKUP):
        sys.exit(f"AppleMobileBackup not found at {APPLE_MOBILE_BACKUP}")
    start_size = await asyncio.to_thread(dir_size, device_dir) if device_dir.exists() else 0
    proc = await asyncio.create_subprocess_exec(APPLE_MOBILE_BACKUP, "--backup", "--target", udid)
    t0 = time.time()
    du_every = DU_SECONDS_FULL if first_run else DU_SECONDS_INCREMENTAL

    async def heartbeat():
        size, measured_at = start_size, 0.0
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            el = time.time() - t0
            if el - measured_at >= du_every:
                size, measured_at = await asyncio.to_thread(dir_size, device_dir), el
            if PROMPTING.is_set():
                continue
            written = max(size - start_size, 0)
            rate = written / max(measured_at, 1)
            line = f"elapsed {el:4.0f}s | written {human(written)} ({human(rate)}/s)"
            if first_run and expected_bytes:
                # Use the whole folder: an interrupted earlier attempt already left part of this full backup
                pct = min(size / expected_bytes * 100, 99.9)
                line = f"~{pct:4.1f}% of ~{human(expected_bytes)} | " + line
                if rate:
                    line += f" | ETA ~{max(expected_bytes - size, 0) / rate / 60:.0f} min"
            print(f"\r    [progress] {line}   ", end="", flush=True)

    hb = asyncio.create_task(heartbeat())
    try:
        rc = await proc.wait()
    except asyncio.CancelledError:
        proc.terminate()
        raise
    finally:
        hb.cancel()
        print()
    if rc != 0:
        sys.exit(f"AppleMobileBackup failed (exit code {rc})")


async def backup_encryption(lockdown) -> bool:
    """Whether the device encrypts its backups (logged).

    iOS has no WillEncrypt value at all until backup encryption was turned on once: lockdown
    answers MissingValue, which means the backup is not encrypted.
    """
    try:
        will_encrypt = bool(await lockdown.get_value("com.apple.mobile.backup", "WillEncrypt"))
    except MissingValueError:
        will_encrypt = False
    log(f"Device backup encryption: {'ON' if will_encrypt else 'OFF'}")
    if not will_encrypt:
        log("NOTE: unencrypted backup -> no keychain items, and the device data is stored unencrypted "
            "on this Mac. To include them, enable 'Encrypt local backup' for this iPhone in Finder")
    return will_encrypt


async def device_used_bytes(lockdown):
    try:
        usage = await lockdown.get_value("com.apple.disk_usage")
        return usage["TotalDataCapacity"] - usage["TotalDataAvailable"]
    except Exception:
        return None


async def check_disk_space(lockdown, target: Path):
    """Warn before a first full Finder-style backup that would not fit on disk."""
    needed = await device_used_bytes(lockdown)
    if not needed:
        return
    free = shutil.disk_usage(target).free
    log(f"iPhone used ~{human(needed)}, Mac free {human(free)}")
    if free < needed * 1.1:
        if input("Mac may not have enough free space for a full backup. Continue? [y/N] ").strip().lower() != "y":
            sys.exit("Aborted.")


async def pull_container(lockdown, bundle_id, data_dir: Path, documents_only: bool):
    """Copy the app container directly over AFC (house_arrest), no backup needed.

    VendContainer (whole container, incl. Library/Caches and tmp) is allowed by iOS for
    development-signed and TestFlight builds; VendDocuments (Documents only) for File Sharing
    apps. Files land in data_dir/AppDomain-<bundleID>/, the same layout as a backup extraction.
    Returns the number of files copied, or None if iOS refuses to vend the container.
    """
    try:
        service = await HouseArrestService.create(lockdown, bundle_id, documents_only=documents_only)
    except PyMobileDevice3Exception as e:
        log(f"{'VendDocuments' if documents_only else 'VendContainer'} refused by iOS ({e})")
        return None
    root = data_dir / f"AppDomain-{bundle_id}"
    root.mkdir(parents=True, exist_ok=True)
    count = [0]

    def on_file(src, dst):
        count[0] += 1
        print(f"\r    pulled {count[0]} files | {src[-50:]:50}", end="", flush=True)

    skipped, unreadable = [], []

    def collect_ignored(record):
        # pull(ignore_errors=True) warns once per unreadable file (e.g. WebKit cache blobs): collect
        # instead, and drop the empty local file pull() already created for it
        msg = record.getMessage()
        if not msg.startswith("(Ignoring)"):
            return True
        unreadable.append(msg)
        src = msg.rpartition(" occurred during the copy of ")[2]
        try:
            local = safe_join(root, src.lstrip("/")) if src.startswith("/") else None
        except ValueError:  # raising inside a logging filter would abort the whole pull
            local = None
        if local is not None and local.is_file() and local.stat().st_size == 0:
            local.unlink()
        return False

    service.logger.addFilter(collect_ignored)
    try:
        # Pull top-level entries one by one: some (container metadata plist, SystemData) are not
        # readable over AFC, which aborts a pull of "/" despite ignore_errors
        sources = ["/Documents"] if documents_only else [f"/{n}" for n in await service.listdir("/")]
        for src in sources:
            try:
                await service.pull(src, str(root), callback=on_file, ignore_errors=True, progress_bar=False)
            except PyMobileDevice3Exception:
                skipped.append(src)
    finally:
        await service.close()
        print()
    if skipped:
        log(f"Not readable over AFC (skipped): {', '.join(skipped)}")
    if unreadable:
        errors_log = data_dir.parent / "afc_unreadable.log"
        errors_log.write_text("\n".join(unreadable) + "\n")
        log(f"{len(unreadable)} file(s) could not be opened over AFC (list: {errors_log})")
    return count[0]


# ---------------------------------------------------------------- Finder backups (-bk)
def read_plist(path: Path) -> dict:
    try:
        with open(path, "rb") as fd:
            return plistlib.load(fd)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return {}


def finder_backups():
    return scan_backups(FINDER_BACKUP_ROOT)


def scan_backups(root: Path):
    """Standard (Finder-format) backups in root, oldest first, described from Manifest/Status.plist.

    A folder named "<UDID>-YYYYMMDD-HHMMSS" is an older copy that the backup engine renamed
    aside when it started a new backup of that device.
    """
    if not root.is_dir():
        return []
    dirs = [d for d in root.iterdir()
            if d.is_dir() and ((d / "Manifest.plist").is_file() or (d / "Status.plist").is_file())]
    with ThreadPoolExecutor() as ex:
        sizes = list(ex.map(lambda d: dir_size(d, background=False), dirs))
    rows = []
    for d, size in zip(dirs, sizes):
        manifest, status = read_plist(d / "Manifest.plist"), read_plist(d / "Status.plist")
        dev = manifest.get("Lockdown") or {}
        when = status.get("Date") or manifest.get("Date")  # plist dates are naive UTC
        when = when.replace(tzinfo=timezone.utc).astimezone() if isinstance(when, datetime) \
            else datetime.fromtimestamp(d.stat().st_mtime).astimezone()
        udid = dev.get("UniqueDeviceID") or d.name.split("-20")[0]
        rows.append({"folder": d.name, "path": d, "udid": udid, "name": clean_text(dev.get("DeviceName")) or "?",
                     "model": dev.get("ProductType", "?"), "ios": dev.get("ProductVersion", "?"), "date": when,
                     "size": size, "encrypted": bool(manifest.get("IsEncrypted")), "old_copy": d.name != udid,
                     "complete": status.get("SnapshotState") == "finished" and (d / "Manifest.db").is_file()})
    return sorted(rows, key=lambda r: r["date"])


def age_text(delta) -> str:
    sec = max(delta.total_seconds(), 0)
    if sec >= 86400:
        return f"{sec // 86400:.0f}d"
    return f"{sec // 3600:.0f}h" if sec >= 3600 else f"{sec // 60:.0f}m"


async def print_backups(older_than=None):
    rows = finder_backups()
    if older_than is not None:
        rows = [r for r in rows if datetime.now().astimezone() - r["date"] >= timedelta(days=older_than)]
    print_backup_table(rows, await connected_udids())
    scope = f" at least {older_than} day(s) old" if older_than is not None else ""
    print(f"\n{len(rows)} backup(s){scope}, {human(sum(r['size'] for r in rows))} in {FINDER_BACKUP_ROOT}")
    caches = [d for d in CACHE_ROOT.iterdir() if d.is_dir()] if CACHE_ROOT.is_dir() else []
    if caches:
        print(f"pmd3 per-app caches: {len(caches)} in {CACHE_ROOT} ({human(dir_size(CACHE_ROOT, background=False))})")
    if rows:
        print(f"Delete: {Path(sys.argv[0]).name} --delete-backup <FOLDER> [<FOLDER> ...]   (asks before deleting)")


async def connected_udids():
    try:
        return {d.serial for d in await list_devices()}
    except Exception:  # usbmuxd not reachable: just no "connected" mark
        return set()


def print_table(header, rows, indent=""):
    table = [header] + rows
    widths = [max(len(t[c]) for t in table) for c in range(len(header))]
    for t in table if rows else []:
        print(indent + "  ".join(f"{v:{w}}" for v, w in zip(t, widths)).rstrip())


def print_backup_table(rows, connected=frozenset(), indent=""):
    now = datetime.now().astimezone()
    header = ("FOLDER", "DEVICE", "MODEL", "iOS", "LAST BACKUP", "AGE", "SIZE", "ENC", "NOTES")
    table = [header]
    for r in rows:
        notes = [n for n, on in (("OLD COPY", r["old_copy"]), ("INCOMPLETE", not r["complete"]),
                                 ("connected", r["udid"] in connected and not r["old_copy"])) if on]
        table.append((r["folder"], r["name"][:20], r["model"], r["ios"], f"{r['date']:%Y-%m-%d %H:%M}",
                      age_text(now - r["date"]), human(r["size"]), "yes" if r["encrypted"] else "no", ", ".join(notes)))
    print_table(header, table[1:], indent)


def epoch_text(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"


async def print_imazing():
    """iMazing: where it keeps backups, what is in there, and which devices it knows.

    iMazing uses the same backup protocol and folder format as Finder (current backup in
    <location>/<UDID>/), plus older versions in its own incremental format under
    <location>/iMazing.Versions/Versions/<UDID>/ (managed by iMazing only).
    """
    prefs_dir = IMAZING_ROOT / "Prefs"
    if not prefs_dir.is_dir():
        print(f"iMazing not found ({prefs_dir} does not exist)")
        return
    prefs = read_plist(prefs_dir / "Prefs.plist")
    devices = read_plist(prefs_dir / "Devices.plist")
    default = prefs.get("DefaultBackupRootPath") or str(IMAZING_ROOT / "Backups")
    locations = [default] + list(read_plist(prefs_dir / "BackupLocations.plist")) \
        + [d.get("backupRootPath") for d in devices.values() if isinstance(d, dict)]
    locations = list(dict.fromkeys(filter(None, locations)))  # unique, keep order
    connected = await connected_udids()

    print(f"iMazing settings: {prefs_dir}")
    print("Backup locations:")
    for loc in locations:
        path = Path(loc)
        tags = [t for t, on in (("default", loc == default), ("shared with Finder, see -bk", path == FINDER_BACKUP_ROOT),
                                ("MISSING", not path.is_dir())) if on]
        size = human(dir_size(path, background=False)) if path.is_dir() else "-"
        print(f"  {loc}  ({size}{', ' + ', '.join(tags) if tags else ''})")

    total = 0
    for loc in locations:
        path = Path(loc)
        if not path.is_dir():
            continue
        rows = scan_backups(path)
        versions_root = path / "iMazing.Versions" / "Versions"
        archives = []
        for d in sorted(versions_root.iterdir()) if versions_root.is_dir() else []:
            if d.is_dir():
                entries = [e for e in d.iterdir() if not e.name.startswith(".")]
                name = (devices.get(d.name) or {}).get("name", "?")
                archives.append((d.name, clean_text(name), str(len(entries)), human(dir_size(d, background=False)),
                                 epoch_text(max((e.stat().st_mtime for e in entries), default=0))))
        total += sum(r["size"] for r in rows)
        print(f"\n== {loc}")
        if rows:
            print_backup_table(rows, connected, indent="  ")
        else:
            print("  no standard backups")
        if archives:
            print("  Archived versions (iMazing.Versions/Versions, manage them in iMazing only):")
            print_table(("UDID", "DEVICE", "VERSIONS", "SIZE", "LATEST"), archives, indent="    ")

    print("\nDevices known to iMazing (Devices.plist):")
    rows = []
    for udid, d in sorted(devices.items(), key=lambda kv: -(kv[1].get("timeLastConnection") or 0)
                          if isinstance(kv[1], dict) else 0):
        if not isinstance(d, dict):
            continue
        last_backup = max(d.get("timeLastBackup") or 0, d.get("timeLastTrueOrPartialBackup") or 0)
        rows.append((udid + (" *" if udid in connected else ""), clean_text(d.get("name"))[:24],
                     str(d.get("productType", "?")), str(d.get("productVersion", "?")),
                     epoch_text(d.get("timeLastConnection")), epoch_text(last_backup), str(d.get("totalBackups", 0))))
    print_table(("UDID", "NAME", "MODEL", "iOS", "LAST CONNECTED", "LAST BACKUP", "BACKUPS"), rows, indent="  ")
    print(f"\n{len(rows)} device(s); * = connected now. Standard backups found: {human(total)}")


def backup_running(udid) -> bool:
    out = subprocess.run(["pgrep", "-fl", "AppleMobileBackup"], capture_output=True, text=True).stdout
    return udid in out


def delete_backups(folders):
    """Delete Finder backup folders by their exact name from -bk, each after a y/N confirmation."""
    rows = {r["folder"]: r for r in finder_backups()}
    for folder in folders:
        r = rows.get(folder.rstrip("/"))
        if r is None:  # only names from the listing: never an arbitrary path
            log(f"No backup folder named {folder!r} in {FINDER_BACKUP_ROOT} (see -bk)")
            continue
        if not r["old_copy"] and backup_running(r["udid"]):
            log(f"Skipping {folder}: a backup of this iPhone is running right now")
            continue
        answer = input(f"Delete {r['folder']} ({r['name']}, {r['model']}, {r['date']:%Y-%m-%d %H:%M}, "
                       f"{human(r['size'])})? [y/N] ").strip().lower()
        if answer != "y":
            log("Kept")
            continue
        shutil.rmtree(r["path"])
        log(f"Deleted {r['path']} ({human(r['size'])} freed)"
            + ("" if r["old_copy"] else "; next backup of this iPhone will be a FULL one"))


# ---------------------------------------------------------------- host side
def is_encrypted(device_dir: Path) -> bool:
    with open(device_dir / "Manifest.plist", "rb") as fd:
        return bool(plistlib.load(fd).get("IsEncrypted"))


def safe_join(base: Path, *parts: str) -> Path:
    """Join device-supplied path parts under base; refuse anything resolving outside it.

    is_relative_to compares whole path components: a string prefix check would let
    "../data2/x" through for base ".../data" (".../data2" starts with ".../data").
    """
    base = base.resolve()
    out = base.joinpath(*parts).resolve()
    if not out.is_relative_to(base):
        raise ValueError(f"unsafe path: {parts}")
    return out


def domain_where(bundle_id, group_ids):
    clauses = ["domain = ?", "domain LIKE ?"] + ["domain = ?"] * len(group_ids)
    params = [f"AppDomain-{bundle_id}", f"AppDomainPlugin-{bundle_id}.%"] + [f"AppDomainGroup-{g}" for g in group_ids]
    return " OR ".join(clauses), params


def extract_plain(device_dir: Path, out_dir: Path, bundle_id, group_ids):
    where, params = domain_where(bundle_id, group_ids)
    db = sqlite3.connect(f"file:{device_dir / 'Manifest.db'}?mode=ro", uri=True)
    rows = db.execute(f"SELECT fileID, domain, relativePath, flags FROM Files WHERE {where}", params).fetchall()
    db.close()
    n = missing = 0
    for file_id, domain, rel, flags in rows:
        dst = safe_join(out_dir, domain, rel) if rel else safe_join(out_dir, domain)
        if flags == 2:
            dst.mkdir(parents=True, exist_ok=True)
            continue
        if flags != 1:
            continue
        src = device_dir / file_id[:2] / file_id
        if not src.exists():
            missing += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        n += 1
    return n, missing


def ask_password(prompt="Backup is ENCRYPTED. Enter backup password: "):
    pw = os.environ.get("IOS_BACKUP_PASSWORD")
    if not pw:
        PROMPTING.set()
        try:
            print(clear_line(), end="", flush=True)
            pw = getpass.getpass(prompt)
        except EOFError:  # stdin closed / not interactive
            pw = ""
        finally:
            PROMPTING.clear()
    if not pw:
        sys.exit("Empty password, abort.")
    return pw


def read_keybag(device_dir: Path) -> bytes:
    with open(device_dir / "Manifest.plist", "rb") as fd:
        return plistlib.load(fd)["BackupKeyBag"]


def derive_key(keybag: bytes, password, key=None):
    """Key unlocking this backup keybag: `key` if it still fits, else PBKDF2 of the password, else None."""
    if key is not None and BackupKeyBag(keybag).unlock_with_key(key):
        return key
    if password is None:
        return None
    kb = BackupKeyBag(keybag)
    return kb.passphrase_key if kb.unlock_with_passphrase(password.encode()) else None


def unlock_keybag(keybag: bytes, password=None, key=None):
    """Return (password, key) that unlock the keybag, asking for the password if needed.

    The derived key is reused afterwards, so the slow PBKDF2 runs once per run (again only if
    the new backup's keybag no longer matches the key).
    """
    for attempt in range(1, MAX_PASSWORD_TRIES + 1):
        if password is None and key is None:
            password = ask_password()
        found = derive_key(keybag, password, key)
        if found:
            return password, found
        log(f"Wrong backup password ({attempt}/{MAX_PASSWORD_TRIES})")
        password = key = None
        os.environ.pop("IOS_BACKUP_PASSWORD", None)
    sys.exit("Wrong backup password. Abort (raw backup kept for retry with --skip-backup).")


def extract_encrypted(backup: EncryptedBackup, device_dir: Path, out_dir: Path, bundle_id, group_ids):
    total = 0
    patterns = [f"AppDomain-{bundle_id}", f"AppDomainPlugin-{bundle_id}.%"] + [f"AppDomainGroup-{g}" for g in group_ids]

    def present(*, file_id, **_):
        # Skip entries listed in Manifest.db whose payload was not stored
        return (device_dir / file_id[:2] / file_id).is_file()

    for dom in patterns:
        total += backup.extract_files(relative_paths_like="%", domain_like=dom, output_folder=str(out_dir),
                                      preserve_folders=True, domain_subfolders=True, filter_callback=present)
    for _, domain, rel, _ in backup.get_folders(domain_like=f"AppDomain%{bundle_id}%"):
        safe_join(out_dir, domain, rel).mkdir(parents=True, exist_ok=True)
    return total


def check_library_versions():
    """Warn when installed libraries differ from the tested ones (some of their internals are used)."""
    for pkg, tested in TESTED_VERSIONS.items():
        try:
            installed = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            continue
        if installed != tested:
            log(f"WARNING: {pkg} {installed} installed, script tested with {tested}. If something breaks: "
                f"uv tool install --force ios-app-container (reinstalls the pinned versions)")


# ---------------------------------------------------------------- main
def tool_version():
    try:
        return importlib.metadata.version("ios-app-container")
    except importlib.metadata.PackageNotFoundError:
        return "unknown (not installed as a package)"


async def main():
    ap = argparse.ArgumentParser(description="Backup iPhone over USB and extract one app's data.")
    ap.add_argument("app", nargs="?", help="Bundle ID (e.g. com.example.app) or app name")
    ap.add_argument("-o", "--output", help=f"Output folder (default: {OUTPUT_ROOT}/<bundleID>_<timestamp>)")
    ap.add_argument("--udid", help="Device UDID (see -d). Default: the only connected device; asks when several")
    ap.add_argument("-l", "--list", action="store_true",
                    help="List user apps (name, bundle ID, version, signing) and exit; "
                         "Dev/TestFlight apps can be copied directly without a backup")
    ap.add_argument("-ld", "--list-direct", action="store_true",
                    help="Like --list, but only Dev/TestFlight apps (container copied directly, no backup)")
    ap.add_argument("-d", "--devices", action="store_true",
                    help="List connected iPhones (name, model, iOS, UDID, USB/Wi-Fi) and exit")
    ap.add_argument("-bk", "--backups", action="store_true",
                    help=f"List Finder backups in {FINDER_BACKUP_ROOT} (device, date, age, size), oldest first, "
                         "and exit; no iPhone needed")
    ap.add_argument("-imazing", "--imazing", action="store_true",
                    help="Show iMazing's backup folders, the backups in them and the devices iMazing knows, "
                         "and exit; no iPhone needed")
    ap.add_argument("--older-than", type=int, metavar="DAYS", help="With -bk: only backups at least DAYS days old")
    ap.add_argument("--delete-backup", nargs="+", metavar="FOLDER",
                    help="Delete Finder backup folder(s) as named by -bk, asking y/N for each, and exit")
    ap.add_argument("-v", "--version", action="version", version=f"%(prog)s {tool_version()}",
                    help="Show the tool version and exit")
    ap.add_argument("--verbose", action="store_true",
                    help="pymobiledevice3 log; with --engine pmd3 also every file received (KEEP/skip) "
                         "+ heartbeat every 10s")
    ap.add_argument("--engine", choices=ENGINES,
                    help=f"Backup engine: finder = Apple's AppleMobileBackup into {FINDER_BACKUP_ROOT} "
                         "(whole backup kept -> fast incremental); pmd3 = pymobiledevice3, keeps only the "
                         f"app's files in {CACHE_ROOT}/<bundleID>. Default: ${ENGINE_ENV} or finder")
    ap.add_argument("--finder", action="store_const", dest="engine", const="finder",
                    help="Same as --engine finder (the default; kept for old commands)")
    ap.add_argument("--full", action="store_true", help="[pmd3] Force a full backup instead of incremental")
    ap.add_argument("--no-filter", action="store_true", help="[pmd3] Store the whole device backup (no filtering)")
    ap.add_argument("--backup-dir", help=f"[pmd3] Raw backup cache folder (default: {CACHE_ROOT}/<bundleID>)")
    ap.add_argument("--clean", action="store_true", help="[pmd3] Delete the raw backup cache after extraction")
    ap.add_argument("--skip-backup", action="store_true",
                    help="Do not back up again, extract from the existing backup (Finder backup, or the "
                         "per-app cache with --engine pmd3)")
    ap.add_argument("--force-backup", action="store_true",
                    help="Always do a backup, even if the container can be copied directly "
                         "(dev/TestFlight build or File Sharing app); needed for App Group data")
    ap.add_argument("--no-open", action="store_true", help="Do not open the output folder in Finder at the end")
    ap.add_argument("--save-manifest", action="store_true",
                    help="Also save the decrypted Manifest.db (lists EVERY file path on the device)")
    args = ap.parse_args()
    if args.engine is None:
        args.engine = os.environ.get(ENGINE_ENV, "finder")
        if args.engine not in ENGINES:
            ap.error(f"${ENGINE_ENV}={args.engine!r}: must be one of {', '.join(ENGINES)}")
    pmd3_only = [opt for opt, val in (("--full", args.full), ("--no-filter", args.no_filter),
                                      ("--backup-dir", args.backup_dir), ("--clean", args.clean)) if val]
    if pmd3_only and args.engine != "pmd3":
        ap.error(f"{', '.join(pmd3_only)}: only for --engine pmd3 (current engine: {args.engine})")
    # asyncio.run's SIGINT handler only schedules a task cancellation, which cannot happen while
    # the main thread sits in a blocking prompt (password, "Choose number"), so the first Ctrl-C
    # was swallowed there. The default handler raises KeyboardInterrupt right away.
    if signal.getsignal(signal.SIGINT) is not signal.SIG_IGN:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    if args.older_than is not None and not args.backups:
        ap.error("--older-than only works with -bk")
    if args.backups:
        await print_backups(args.older_than)
        return
    if args.imazing:
        await print_imazing()
        return
    if args.devices:
        await print_devices()
        return
    if args.delete_backup:
        delete_backups(args.delete_backup)
        return
    check_library_versions()
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="    [%(name)s] %(message)s")
        logging.getLogger("pymobiledevice3").setLevel(logging.INFO)

    lockdown = await connect_device(args.udid)
    # Close the SSL lockdown session while the loop is alive: otherwise it is finalized after
    # asyncio.run closed the loop and Python 3.10 prints "Fatal error on SSL transport".
    try:
        log(f"Device: {lockdown.display_name} ({lockdown.product_type}, iOS {lockdown.product_version}) "
            f"UDID={lockdown.udid}{connection_text(lockdown)}")
        apps = await get_user_apps(lockdown)

        if args.list or args.list_direct:
            print_app_list(apps, direct_only=args.list_direct)
            return
        if not args.app:
            ap.error("app (bundle ID or name) is required")

        bundle_id = resolve_app(apps, args.app)
        info = apps[bundle_id]
        group_ids = list((info.get("GroupContainers") or {}).keys())
        log(f"App: {info.get('CFBundleDisplayName') or info.get('CFBundleName')} ({bundle_id}) "
            f"v{info.get('CFBundleShortVersionString')} | FileSharing={bool(info.get('UIFileSharingEnabled'))}")
        log(f"Container: {info.get('Container')}")
        for g, p in (info.get("GroupContainers") or {}).items():
            log(f"AppGroup : {g} -> {p}")
        log(f"Engine   : {args.engine} (used only if a backup is needed)")

        out_dir = Path(args.output).expanduser().resolve() if args.output \
            else OUTPUT_ROOT / f"{bundle_id}_{datetime.now():%Y%m%d_%H%M%S}"
        created = not out_dir.exists()
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            await extract_to(args, lockdown, info, bundle_id, group_ids, out_dir)
        except BaseException:
            # Failed or interrupted run (wrong password, Ctrl-C, device error): do not leave behind
            # the output folder this run created if nothing was extracted into it
            if created and not any(p.is_file() for p in out_dir.rglob("*")):
                shutil.rmtree(out_dir, ignore_errors=True)
                log(f"Removed empty output folder {out_dir}")
            raise
    finally:
        with contextlib.suppress(Exception):
            await lockdown.close()


async def extract_to(args, lockdown, info, bundle_id, group_ids, out_dir: Path):
    if not args.force_backup and not args.skip_backup:
        data_dir = out_dir / "data"
        t0 = time.time()
        log("Trying direct container copy (house_arrest VendContainer, works for dev/TestFlight builds)...")
        n = await pull_container(lockdown, bundle_id, data_dir, documents_only=False)
        if n is not None:
            log(f"Copied whole container: {n} files in {time.time() - t0:.1f}s (no backup needed)")
            if group_ids:
                log("NOTE: App Group containers are not reachable this way; use --force-backup to get them")
            print_summary(data_dir, not args.no_open)
            return
        if info.get("UIFileSharingEnabled"):
            log("App has File Sharing enabled -> copying Documents directly (no backup)")
            n = await pull_container(lockdown, bundle_id, data_dir, documents_only=True)
            if n is not None:
                log(f"Copied {n} files in {time.time() - t0:.1f}s. Use --force-backup to also get Library/")
                print_summary(data_dir, not args.no_open)
                return
        log("-> falling back to a backup")

    if args.engine == "finder":
        await run_finder_mode(args, lockdown, out_dir, bundle_id, group_ids)
    else:
        await run_pmd3_mode(args, lockdown, info, out_dir, bundle_id, group_ids)


def previous_keybag(device_dir: Path):
    """Keybag of the previous encrypted backup in device_dir, or None.

    Read it before the new backup starts: the backup engine rewrites Manifest.plist while it runs.
    """
    if (device_dir / "Manifest.plist").is_file() and is_encrypted(device_dir):
        return read_keybag(device_dir)
    return None


async def password_during_backup(backup: asyncio.Task, old_keybag):
    """Ask the backup password while the backup runs, so typing it and PBKDF2 cost no extra time.

    The password is checked against the previous backup's keybag when there is one; otherwise
    only after the backup. Returns (password, key); key is None when nothing could be checked.
    """
    try:
        if old_keybag is not None:
            password, key = await in_daemon_thread(unlock_keybag, old_keybag)
            log("Backup password verified against the previous backup (backup still running)")
            return password, key
        password = await in_daemon_thread(ask_password, "Backup encryption is ON. Enter backup "
                                                         "password (checked after the backup): ")
        return password, None
    except SystemExit as e:
        log(f"{e} Waiting for the backup to finish so it stays consistent...")
        await backup
        raise


async def run_pmd3_mode(args, lockdown, info, out_dir, bundle_id, group_ids):
    """pymobiledevice3 engine: only the app's files are written, into a small per-app cache."""
    password = key = None
    default_cache = CACHE_ROOT / ("_all" if args.no_filter else bundle_id)
    backup_dir = Path(args.backup_dir).expanduser().resolve() if args.backup_dir else default_cache
    backup_dir.mkdir(parents=True, exist_ok=True)
    if not args.skip_backup:
        cached = backup_dir / lockdown.udid
        marker = backup_dir / FILTER_MARKER
        has_cache = (cached / "Manifest.db").is_file()
        marker_ok = args.no_filter or (marker.is_file() and marker.read_text().strip() == FILTER_VERSION)
        incremental = not args.full and has_cache and marker_ok
        if has_cache and not marker_ok and not args.full:
            log("Cache was made by an older filter (app files may be missing) -> forcing FULL backup")
        log(f"Backup cache: {backup_dir} -> {'INCREMENTAL' if incremental else 'FULL (slow: whole device is streamed)'}")
        will_encrypt = await backup_encryption(lockdown)
        old_keybag = previous_keybag(cached)

        async def backup_and_mark():
            await do_backup(lockdown, backup_dir, None if args.no_filter else make_filter(info, bundle_id),
                            full=not incremental, verbose=args.verbose)
            # Inside the task: a finished backup is marked even if the password check fails meanwhile
            if not args.no_filter:
                marker.write_text(FILTER_VERSION)

        log("Starting backup... (unlock the iPhone; iOS may ask for the device passcode to allow the backup)")
        t0 = time.time()
        backup = asyncio.create_task(backup_and_mark())
        if will_encrypt:
            password, key = await password_during_backup(backup, old_keybag)
        await backup
        log(f"Backup done in {time.time() - t0:.0f}s -> {backup_dir}")

    data_dir = extract_app(backup_dir / lockdown.udid, out_dir, bundle_id, group_ids, password, key,
                           args.save_manifest)
    if args.clean:
        shutil.rmtree(backup_dir, ignore_errors=True)
        log("Raw backup cache deleted")
    print_summary(data_dir, not args.no_open)


async def run_finder_mode(args, lockdown, out_dir, bundle_id, group_ids):
    """Finder engine (default): Apple's AppleMobileBackup keeps the whole device backup."""
    device_dir = FINDER_BACKUP_ROOT / lockdown.udid
    has_backup = (device_dir / "Manifest.db").is_file()
    password = key = None
    if not args.skip_backup:
        log(f"Finder backup: {device_dir} -> "
            f"{'INCREMENTAL (only changes are sent)' if has_backup else 'FIRST FULL backup (slow, whole device)'}")
        if not has_backup:
            FINDER_BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
            await check_disk_space(lockdown, FINDER_BACKUP_ROOT)
        will_encrypt = await backup_encryption(lockdown)
        old_keybag = previous_keybag(device_dir)
        expected = await device_used_bytes(lockdown)
        log("Starting AppleMobileBackup... (unlock the iPhone; iOS may ask for the device passcode)")
        t0 = time.time()
        backup = asyncio.create_task(finder_backup(lockdown.udid, device_dir, expected, first_run=not has_backup))
        if will_encrypt:
            password, key = await password_during_backup(backup, old_keybag)
        await backup
        log(f"Backup done in {time.time() - t0:.0f}s")
    data_dir = extract_app(device_dir, out_dir, bundle_id, group_ids, password, key, args.save_manifest)
    print_summary(data_dir, not args.no_open)

def extract_app(device_dir: Path, out_dir: Path, bundle_id, group_ids, password, key, save_manifest):
    if not (device_dir / "Manifest.plist").exists():
        sys.exit(f"No backup found at {device_dir}")
    data_dir = out_dir / "data"
    data_dir.mkdir(exist_ok=True)
    if is_encrypted(device_dir):
        log("Backup is encrypted -> decrypting")
        password, key = unlock_keybag(read_keybag(device_dir), password, key)
        backup = EncryptedBackup(backup_directory=str(device_dir), passphrase_key=key)
        n = extract_encrypted(backup, device_dir, data_dir, bundle_id, group_ids)
        if save_manifest:
            backup.save_manifest_file(str(out_dir / "Manifest_decrypted.db"))
        log(f"Extracted {n} files")
    else:
        n, missing = extract_plain(device_dir, data_dir, bundle_id, group_ids)
        log(f"Extracted {n} files" + (f" ({missing} listed but not in backup)" if missing else ""))
    return data_dir


def print_summary(data_dir: Path, open_folder=True):
    log(f"Output: {data_dir}")
    for d in sorted(data_dir.iterdir()):
        cnt = sum(1 for p in d.rglob("*") if p.is_file())
        print(f"    {d.name}/  ({cnt} files)")
    if open_folder:
        subprocess.run(["open", str(data_dir)], check=False)


def cli():
    """Console entry point (ios-app-container)."""
    # A password prompt runs in a daemon thread during the backup; if the script exits while it
    # waits, getpass never restores terminal echo -> restore the saved terminal state ourselves.
    tty_state = termios.tcgetattr(sys.stdin) if sys.stdin.isatty() else None
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
    finally:
        if tty_state is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, tty_state)


if __name__ == "__main__":
    cli()
