# ios-app-container

Extract the data of **one app** from an iPhone over USB or Wi-Fi: its app container (`Documents`, `Library`, …), and when going through a backup also its App Group and extension containers. Works for apps that do **not** enable File Sharing.

## Install

**macOS only** (it uses Apple's backup engine that ships with macOS). Requires [uv](https://docs.astral.sh/uv/) (or `pipx`).

```bash
uv tool install ios-app-container                                 # from PyPI
uv tool install git+https://github.com/dovantuit/ios-app-container   # or straight from GitHub
```

Then run `ios-app-container`. Uninstall with `uv tool uninstall ios-app-container`.

- Works on Apple silicon and Intel Macs, with arm64 or x86_64 (Rosetta) Python; no compiler or Rust needed.
- From source, for development: `uv tool install --editable .` in the repo folder.
- Library versions are **pinned** because the tool uses some of their internals. When the installed versions differ from the tested ones, the tool prints a `WARNING`; reinstall with `uv tool install --force ios-app-container`.
- The iPhone must be **unlocked** and must have **trusted** this Mac.
- No cable needed once Wi-Fi sync is on: connect the cable once → Finder → select the iPhone → General → tick **Show this iPhone when on Wi-Fi** → Apply. The Mac and the iPhone must be on the same Wi-Fi network. The `Device:` line printed at start says `via USB` or `via Wi-Fi`. Wi-Fi is much slower (direct copy of ~30 files: ~18s vs ~2s over the cable), so do the first full backup over the cable.

## Quick start

```bash
ios-app-container -d                  # connected iPhones (UDID, USB / Wi-Fi)
ios-app-container -l                  # apps on the iPhone (bundle ID, version, signing)
ios-app-container com.example.app     # extract by bundle ID
ios-app-container "Example App"       # or by app name (partial match works)
ios-app-container -bk                 # backups taking space on this Mac
ios-app-container -imazing            # iMazing backup folders and backups
```

When done, the output folder opens in Finder (`--no-open` to skip).

**Several iPhones connected** (cable or Wi-Fi): without `--udid` the tool lists them and asks you to pick a number; it never picks one silently. The same iPhone on both cable and Wi-Fi counts as one device (`USB+Wi-Fi`, USB is used). When run non-interactively (stdin is not a terminal), it stops and asks for `--udid`.

## How the data is fetched

The tool tries these in order and stops at the first one that works:

| # | Method | Applies to | Time | Gets | Does not get |
|---|---|---|---|---|---|
| 1 | **Direct container copy** (house_arrest VendContainer) | **Dev** and **TestFlight** builds | seconds | The whole container, **incl. `Library/Caches` and `tmp`** | App Groups |
| 2 | **File Sharing** (VendDocuments) | Apps with `UIFileSharingEnabled` | seconds | `Documents/` only | `Library/`, App Groups |
| 3 | **Backup**, then extract the app's files | Any app, incl. App Store builds | minutes (first run: long) | Container, App Groups, extensions | `Library/Caches`, `tmp`, files the app marks "exclude from backup" |

- App Store builds always go through method 3 (iOS refuses method 1 with `InstallationLookupFailed`; that is expected).
- `--force-backup` skips methods 1 and 2 and goes straight to 3. Use it to get the **App Group data** of a Dev/TestFlight build.
- `-ld` lists only Dev/TestFlight apps, i.e. the ones method 1 usually handles.

## Backup engines (method 3)

| Engine | How it works | What it stores on the Mac | Pros | Cons |
|---|---|---|---|---|
| `finder` (**default**) | Apple's backup engine (`AppleMobileBackup`, same as Finder) | **The whole iPhone backup** in `~/Library/Application Support/MobileSync/Backup/<UDID>/` (about the iPhone's used storage) | From the 2nd run on, only changes are sent | Uses Mac disk space |
| `pmd3` | pymobiledevice3 | Only the app's files, in `~/iOSAppBackups/cache/<bundleID>/` (a few MB) | Almost no disk space | The first run still streams the whole device |

```bash
ios-app-container com.example.app                  # finder (default)
ios-app-container com.example.app --engine pmd3    # pmd3
export IOS_APP_EXTRACT_ENGINE=pmd3                 # change the default engine
```

- `--finder` still works (same as `--engine finder`), so older commands keep working.
- `--full`, `--no-filter`, `--backup-dir`, `--clean` **only apply to `--engine pmd3`**; with finder the tool reports an error.

**Measured timings** (an iPhone with ~58GB of data, Lightning cable, USB 2.0):
- First full backup: ~25 min (~19MB/s).
- Incremental backup: ~220s, **even when almost nothing changed**, because iOS scans the whole device. The tool cannot shorten this; the most effective fix is a test iPhone with little data on it.
- A USB-C iPhone is only faster on **Pro/Pro Max** models (USB 3) **with** a separate USB 3 cable, and mostly helps the first full backup.

## Encrypted backups and the password

- If the iPhone encrypts its backups, the tool **asks for the password while the backup is running** (input hidden), so it costs no extra time.
- If a previous backup exists, the password is checked right away; a wrong one is asked again, up to 3 times. After 3 wrong attempts the tool waits for the backup to finish (so it is not left half-done) and exits. Then rerun with `--skip-backup`.
- The password can be preset in the `IOS_BACKUP_PASSWORD` environment variable (careful: it can leak through shell history).
- If the iPhone has **never had backup encryption on**, the tool prints `Device backup encryption: OFF`. An unencrypted backup:
  - has **no keychain** items;
  - stores the whole device's data **unencrypted** on the Mac.

  To turn it on: Finder → select the iPhone → General → **Encrypt local backup**. Do it **before** the first full backup; turning it on later usually forces another full backup.

## Managing backups on the Mac

```bash
ios-app-container -bk                       # list backups, oldest first
ios-app-container -bk --older-than 30       # only backups at least 30 days old
ios-app-container --delete-backup <FOLDER>  # delete (asks y/N for each)
```

Example:
```
FOLDER                                     DEVICE     MODEL       iOS   LAST BACKUP       AGE  SIZE   ENC  NOTES
00008XXX-XXXXXXXXXXXXXXXX-20260101-120000  My iPhone  iPhone16,2  26.5  2026-01-01 12:00  11m  8.8GB  no   OLD COPY
00008XXX-XXXXXXXXXXXXXXXX                  My iPhone  iPhone16,2  26.5  2026-01-01 12:06  5m   8.8GB  no
```

The **NOTES** column:
- `OLD COPY`: an older backup the engine renamed aside when it started a new one (usually after an interrupted backup). Safe to delete.
- `INCOMPLETE`: the backup did not finish.
- `connected`: that iPhone is connected right now.

Notes:
- `--delete-backup` only accepts folder names exactly as listed by `-bk`.
- It refuses to delete the backup of an iPhone that is being backed up.
- Deleting an iPhone's main backup makes its next run a **full backup** again (slow).
- Finder can delete backups too: Finder → select the iPhone → General → **Manage Backups…**

### iMazing backups

```bash
ios-app-container -imazing
```

iMazing uses the same backup protocol and format as Finder. This option reads iMazing's settings (`~/Library/Application Support/iMazing/Prefs`) and prints:

- **iMazing's backup folders** with their size. The default is `~/Library/Application Support/iMazing/Backups`; if iMazing shares `MobileSync/Backup` with Finder, that folder is listed too.
- **The backups in each folder:** the current backup (Finder format, same table as `-bk`) and the **archived versions** in `iMazing.Versions/Versions/<UDID>/`. Archived versions only hold the changes between backups, so **delete or restore them in iMazing only**, never by hand.
- **The devices iMazing has seen** (`Devices.plist`): UDID, name, model, iOS, last connection, last backup, number of backups. `*` marks a connected device. Apple IDs stored in that file are not printed.

No iPhone needed. To open the folder in Finder: `open ~/Library/Application\ Support/iMazing/Backups`

## Where the output goes

Everything lives under `~/iOSAppBackups/` (override with the `IOS_APP_EXTRACT_HOME` environment variable). It is outside `~/Desktop` and `~/Documents` on purpose, because those may be synced to iCloud Drive.

```
~/iOSAppBackups/output/<bundleID>_<timestamp>/
├── data/
│   ├── AppDomain-<bundleID>/             # the app container (Documents, Library, ...)
│   ├── AppDomainGroup-<group ID>/        # App Groups (backup only)
│   └── AppDomainPlugin-<bundleID>.*/     # extensions (backup only)
├── afc_unreadable.log                    # (direct copy) files iOS would not let us read
└── Manifest_decrypted.db                 # only with --save-manifest
```

- Each run creates a new folder; old ones can be deleted freely. Choose another location with `-o <folder>`.
- A run that fails or is interrupted (Ctrl-C) before extracting any file removes its empty output folder. Partially copied data is kept.
- With the direct copy, iOS does not allow reading some files (e.g. WebKit caches). They are listed in `afc_unreadable.log`.

## All options

| Option | Meaning |
|---|---|
| `app` | Bundle ID or app name |
| `-l`, `--list` | List apps (name, bundle ID, version, signing AppStore/TestFlight/Dev, File Sharing) |
| `-ld`, `--list-direct` | List only Dev/TestFlight apps |
| `-d`, `--devices` | List connected iPhones: UDID, name, model, iOS, USB / Wi-Fi |
| `-bk`, `--backups` | List backups on this Mac (no iPhone needed) |
| `--older-than DAYS` | With `-bk`: only backups at least DAYS days old |
| `--delete-backup FOLDER…` | Delete backups by their `-bk` folder name (asks y/N) |
| `-imazing`, `--imazing` | iMazing backup folders, backups and known devices (no iPhone needed) |
| `-o`, `--output DIR` | Output folder |
| `--udid UDID` | Pick the iPhone (UDIDs from `-d`). Without it and with several devices connected, the tool asks |
| `--engine finder\|pmd3` | Backup engine (default: `$IOS_APP_EXTRACT_ENGINE` or `finder`) |
| `--finder` | Same as `--engine finder` |
| `--force-backup` | Always go through a backup (to get App Groups) |
| `--skip-backup` | Do not back up again; extract from the existing backup |
| `--save-manifest` | Also save the decrypted `Manifest.db` (lists **every** file on the iPhone) |
| `--no-open` | Do not open Finder at the end |
| `-v`, `--verbose` | pymobiledevice3 log; with pmd3 also every file received |
| `--full` | [pmd3] Force a full backup |
| `--no-filter` | [pmd3] Store the whole device backup, unfiltered |
| `--backup-dir DIR` | [pmd3] Cache folder |
| `--clean` | [pmd3] Delete the cache after extraction |

Environment variables: `IOS_APP_EXTRACT_ENGINE`, `IOS_APP_EXTRACT_HOME`, `IOS_BACKUP_PASSWORD`.

## Troubleshooting

| Message | Cause / fix |
|---|---|
| `Device … not visible yet` / `Device … not found` | Over Wi-Fi the iPhone drops out of the device list while locked or asleep. The tool retries for 20s; unlock the iPhone (same Wi-Fi as the Mac) or plug the cable. The error lists the devices it can see |
| `VendContainer refused by iOS (InstallationLookupFailed)` | Expected for App Store builds; the tool falls back to a backup |
| `Not readable over AFC (skipped): /.com.apple...metadata.plist, /SystemData` | Expected; iOS does not allow reading these |
| `Wrong backup password (n/3)` | Wrong backup password (the one set when enabling encryption in Finder, not the iPhone passcode) |
| `AppleMobileBackup failed (exit code …)` | iPhone locked or not trusted, loose cable, or the passcode was not entered on the iPhone when iOS asked |
| `Mac may not have enough free space…` | A first full backup needs free space ≈ the iPhone's used storage; free up disk space or use `--engine pmd3` |
| `WARNING: pymobiledevice3 X installed, script tested with Y` | Reinstall the pinned versions: `uv tool install --force ios-app-container` |
| Ctrl-C | Exits immediately; a running Finder backup is stopped too |

## License

GPL-3.0-or-later (see `LICENSE`). Built on [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) (GPL-3.0-or-later) and [iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt) (MIT).

Only use it on devices and data you are authorized to access.
