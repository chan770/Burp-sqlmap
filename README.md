# Burp-sqlmap — Standalone sqlmap for Burp Suite Pro

A Burp Suite Pro extension that runs **sqlmap** directly from Burp on a
locked-down workstation that **cannot install sqlmap — or even Python**.

The extension bundles an embeddable Python runtime *and* the sqlmap source
inside its JAR. On first use it extracts them to a per-user temp directory and
drives sqlmap as a subprocess. Nothing is installed system-wide: no admin
rights, no `pip`, no PATH changes.

---

## Features

- **Zero-install sqlmap** — embeddable CPython + sqlmap are bundled in the jar
  and extracted on first run. Works where you cannot install anything.
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

1. Download `dist/burp-sqlmap.jar` from this repo (it is fully self-contained).
2. Burp → **Extensions → Add → Java** → select the jar.
3. Right-click a request → **Extensions → Standalone sqlmap → Scan with sqlmap**,
   or open the **Standalone sqlmap** suite tab.

The first scan extracts the bundled runtime (a few seconds); subsequent scans are
instant.

> The bundled Python is **Windows amd64** (matching the target workstation). For a
> Linux/macOS Burp host, swap in a portable Python for that platform and adjust
> `RuntimeBootstrap.pythonExe()` (currently `py/python.exe`).

---

## Project layout

```
src/main/java/burpsqlmap/
  SqlmapExtension.java     Montoya entry point: suite tab + context menu
  RuntimeBootstrap.java    Extracts bundled Python + sqlmap from the JAR (once)
  SqlmapRunner.java        Builds the sqlmap command line, runs the subprocess(es)
  ScanOptions.java         UI-selected scan configuration
  SqlmapTab.java           Suite tab: vulnerable-findings panel + tabbed scans
  ScanPanel.java           One request session (native request editor, options, output)
  RenamableTabHeader.java  Double-click-to-rename + closable tab headers
  ScanResultParser.java    Pulls injection points / DBMS / tables / dumped data from output
  ReportGenerator.java     Self-contained HTML report
  IssueReporter.java       Registers a native Burp audit issue (dedup by endpoint)
src/main/resources/
  runtime/python-embed.zip   Embeddable CPython (Windows amd64) — not committed, see below
  runtime/sqlmap.zip         sqlmap source — not committed, see below
  META-INF/services/burp.api.montoya.BurpExtension
test/
  VulnServer.java          Intentionally-vulnerable SQLite-backed demo server
  ParserHarness.java       Offline: output file -> parser -> HTML report
  BootstrapTest.java       Integration: extract runtime from the JAR and run sqlmap
dist/burp-sqlmap.jar       Prebuilt, self-contained extension (~19 MB)
```

---

## Building from source

The bundled runtime zips and the test-only jars are **not committed** (they are
large and re-fetchable; the prebuilt `dist/burp-sqlmap.jar` already contains the
runtime). Fetch them once:

```bash
# Bundled runtime (required to build the extension jar)
curl -L -o src/main/resources/runtime/python-embed.zip \
  https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip
curl -L -o src/main/resources/runtime/sqlmap.zip \
  https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip

# Test target only (VulnServer)
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

`build.ps1` compiles with `javac` and assembles the jar (needs JDK 17+ and
`lib/montoya-api.jar`, which is committed):

```powershell
./build.ps1       # -> dist/burp-sqlmap.jar
```

---

## Testing against the bundled vulnerable server

```powershell
# 1. Build & run the demo target (SQLite-backed, genuinely injectable)
javac --release 17 -cp lib/sqlite-jdbc.jar -d build/test test/VulnServer.java
java -cp "build/test;lib/sqlite-jdbc.jar;lib/slf4j-api.jar" VulnServer 8088
#   -> http://127.0.0.1:8088/product?id=1
```

Proxy `http://127.0.0.1:8088/product?id=1` through Burp, right-click → **Scan with
sqlmap**. Confirmed detection: boolean-based blind, time-based blind and UNION
query on `id`; `back-end DBMS: SQLite`; tables `users` / `products`; with
**Dump all** it also shows the table contents.

### Automated checks

```bash
# Runtime extraction + sqlmap launch, straight from the packaged jar:
java -cp "build/test;dist/burp-sqlmap.jar;lib/montoya-api.jar" burpsqlmap.BootstrapTest
#   -> [test] RESULT: PASS

# Parser + HTML report from captured sqlmap output:
java -cp "build/test;build/classes;lib/montoya-api.jar" ParserHarness sqlmap-output.txt docs/sample-report.html
```

---

## Legal

For **authorized** security testing only. `VulnServer` is deliberately insecure
and binds to `127.0.0.1` — never expose it. You are responsible for having
permission to test any target you point this at.

## License

MIT for the extension source (see [`LICENSE`](LICENSE)). The prebuilt jar bundles
sqlmap (GPL v2.0) and an embeddable CPython (PSF) which are run as a subprocess —
see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
