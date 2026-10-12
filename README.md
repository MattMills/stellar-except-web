StellarStellaris Exception Translator 2.0 - Web App
----------------------------

Upload the `exception.txt` that Stellaris writes when it crashes on Windows, and the app names the
game functions in its stack trace: the frames look like `stellaris.exe  PHYSFS_swapSLE64 (+ 9322603)`
(an exported symbol and an offset), which the app turns into an address in the right build and
then into the function at that address.

2.0 works for every 64-bit Windows build from 2.3.0 on (Steam and GOG, including betas), and it
needs neither a database nor game executables on the server: everything comes from static data
files produced by [stellar-fnmatch](https://github.com/MattMills/stellar-fnmatch).

How it works

- Names come from the PDB files that ship with the GOG builds (and a few early Steam builds).
  stellar-fnmatch matches the functions of every stripped (Steam) build to them, using
  signatures that are unique within each executable, and records a score and the kinds of
  evidence for each name.
- Several builds can share a version number (Steam and GOG, betas, rebuilds). The app checks each
  candidate build: in the right one every return address of the stack falls right after a call
  instruction. Reports from GOG installs are translated against the GOG build and get exact PDB
  names.
- C++ exception-handling funclets are named after the function they belong to. Functions that no
  PDB names (for example SDL's `WinMain`, linked without symbols) are described by the named
  functions they call or are called by.

Files

| file | |
|---|---|
| `index.php` | the page: upload, result table, permalinks (`/cached/<token>`, compatible with 1.x links, which now get 2.0 translations) |
| `api.php` | JSON API: `curl -F file=@exception.txt https://<host>/api.php` (stores nothing) |
| `lib/` | parser, static data reader (binary search with `fseek`), translator, upload storage, configuration |
| `tools/check_corpus.php` | translate a directory of exception.txt files and print per-version counts |

Setup

1. Generate the data with stellar-fnmatch (see its README): `extract`, `sigs`, `match`, then
   `stellar-fnmatch webdata --corpus corpus.json --extract-dir extract --labels-dir runs/<run>/labels --out-dir webdata`.
   The output is metadata only: function ranges, names, call-return addresses and export
   tables. No executable code.
2. Point the app at it in `config.local.php` (see `lib/config.php` for all keys):

       <?php return array('data_dir' => '/srv/stellar-except/webdata', 'uploads_dir' => '/srv/stellar-except/exceptions');

3. Route `/cached/...` to `index.php` (nginx: `try_files $uri $uri/ /index.php?$args;`). PHP 7.4 or
   later; no extensions beyond the defaults.

The uploads directory keeps the 1.x layout (`YYYY/MM/DD/<time>_<ip>.txt`); set `store_uploads` to
false to keep nothing, or `ip_in_filename` to false to leave the address out.

The exec/ directory of 1.x (executables for capstone analysis) was removed from this repo per
discussion with legal@paradoxinteractive.com (Re: 7/18/2023 - 9/29/2023 thread); 2.0 no longer
needs executables, capstone or the stellar-fnaddr database.
