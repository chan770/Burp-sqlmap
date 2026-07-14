# Burp-sqlmap — drive sqlmap from Burp Suite Pro

A Burp Suite Pro extension that runs **sqlmap** directly from Burp against the
requests you already have in Proxy/Repeater/Target — no copy-pasting URLs,
cookies or headers into a terminal.

Nothing is bundled in the jar. You point the extension at a **Python** and a
**sqlmap** that you downloaded yourself (from
[github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)), set
the two paths once in the extension's settings, and go. This keeps the jar tiny
(~50 KB) and lets you use/update whatever sqlmap version you like.

---

## Features

- **Configure once** — a "sqlmap configuration" bar at the top of the tab: set
  the path to your sqlmap folder (or `sqlmap.py`) and, optionally, a Python
  interpreter (blank = `python` on PATH). A **Test** button verifies it by
  running `sqlmap --version`.
- **Right-click → Scan with sqlmap** on any request (Proxy, Repeater, Target …),
  or **Send request to sqlmap tab** to configure before running.
- **Repeater-style tabs** — each request opens its own renamable tab (double-click
  to rename), with a `+` button to add more. Scans run independently/concurrently.
- **Vulnerable findings panel** — a left-hand list of confirmed findings; select
  one to see its injection points, enumerated tables, and dumped table data.
- **Native Burp issues** — confirmed injections are added to **Target → Issues**
  (High / Certain, with request-response evidence), so they appear in Burp's
  issue exports. Duplicate issues for the same endpoint are suppressed.
- **Easy options** — Level/Risk/Threads, Technique and DBMS dropdowns, banner /
  enumerate / dump-all toggles, a free-form extra-args field, and a link to the
  official sqlmap docs.
- **Self-contained HTML report** — see [`docs/sample-report.html`](docs/sample-report.html).

The exact request (headers, cookies, body, method) is passed to sqlmap via `-r`,
so auth and state are preserved; `https` targets automatically get `--force-ssl`.
Scans always run with `--batch --ignore-stdin` (non-interactive, and so sqlmap
never blocks trying to read a targets list from the closed stdin pipe).

---

## Install & use

1. **Get sqlmap** — download/clone it from https://github.com/sqlmapproject/sqlmap
   and extract it somewhere (e.g. `C:\tools\sqlmap`). You also need Python
   (system Python, or a portable/embeddable build if you can't install one).
2. **Load the extension** — download `dist/burp-sqlmap.jar` and add it in Burp →
   **Extensions → Add → Java**.
3. **Point it at your tools** — open the **sqlmap** suite tab and, in the
   *sqlmap configuration* bar, set the **sqlmap** path (folder or `sqlmap.py`)
   and optionally the **Python** path. Click **Save**, then **Test** to confirm.
4. **Scan** — right-click a request → **Extensions → sqlmap → Scan with sqlmap**,
   or send it to the tab and press **Run sqlmap**.

Settings persist across Burp sessions.

> Using an embeddable (zip) Python? Delete its `python3xx._pth` file after
> extracting, otherwise sqlmap's imports fail. A normal Python install needs no
> such tweak.

---

## Project layout

```
src/main/java/burpsqlmap/
  SqlmapExtension.java     Montoya entry point: suite tab + context menu
  SqlmapSettings.java      Persisted Python + sqlmap paths, and path resolution
  SqlmapRunner.java        Builds the sqlmap command line, runs the subprocess(es)
  ScanOptions.java         UI-selected scan configuration
  SqlmapTab.java           Suite tab: config bar + vulnerable-findings panel + tabs
  ScanPanel.java           One request session (native request editor, options, output)
  RenamableTabHeader.java  Double-click-to-rename + closable tab headers
  ScanResultParser.java    Pulls injection points / DBMS / tables / dumped data from output
  ReportGenerator.java     Self-contained HTML report
  IssueReporter.java       Registers a native Burp audit issue (dedup by endpoint)
src/main/resources/
  META-INF/services/burp.api.montoya.BurpExtension
test/
  VulnServer.java          Intentionally-vulnerable SQLite-backed demo server
  ParserHarness.java       Offline: sqlmap output file -> parser -> HTML report
dist/burp-sqlmap.jar       Prebuilt extension (~50 KB; nothing bundled)
```

---

## Building from source

Only `lib/montoya-api.jar` (committed) is needed to build the extension. The
test-only jars are not committed — fetch them if you want to run `VulnServer`:

```bash
curl -L -o lib/sqlite-jdbc.jar \
  https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.45.1.0/sqlite-jdbc-3.45.1.0.jar
curl -L -o lib/slf4j-api.jar \
  https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar
```

### With Gradle

```bash
gradle jar        # -> build/libs/burp-sqlmap-1.0.0.jar
```

### Without Gradle (javac + jar)

```powershell
./build.ps1       # -> dist/burp-sqlmap.jar   (needs JDK 17+ and lib/montoya-api.jar)
```

---

## Testing against the bundled vulnerable server

```powershell
# Build & run the demo target (SQLite-backed, genuinely injectable)
javac --release 17 -cp lib/sqlite-jdbc.jar -d build/test test/VulnServer.java
java -cp "build/test;lib/sqlite-jdbc.jar;lib/slf4j-api.jar" VulnServer 8088
#   -> http://127.0.0.1:8088/product?id=1
```

Proxy `http://127.0.0.1:8088/product?id=1` through Burp, right-click → **Scan with
sqlmap**. Confirmed detection: boolean-based blind, time-based blind and UNION
query on `id`; `back-end DBMS: SQLite`; tables `users` / `products`; with
**Dump all** it also shows the table contents.

```bash
# Parser + HTML report from captured sqlmap output:
java -cp "build/test;build/classes;lib/montoya-api.jar" ParserHarness sqlmap-output.txt docs/sample-report.html
```

---

## Legal

For **authorized** security testing only. `VulnServer` is deliberately insecure
and binds to `127.0.0.1` — never expose it. You are responsible for having
permission to test any target you point this at.

## License

MIT — see [`LICENSE`](LICENSE). sqlmap and Python are **not** bundled or
redistributed here; you supply them yourself. `lib/montoya-api.jar` is provided
by PortSwigger (compile-time), and the test server uses sqlite-jdbc (Apache 2.0);
see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
