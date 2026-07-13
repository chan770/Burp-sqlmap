# Third-party notices

The Burp extension source in this repository is licensed under the MIT License
(see `LICENSE`). To make the extension self-contained ("standalone"), the
prebuilt `dist/burp-sqlmap.jar` **bundles** the following third-party software,
which is run as a separate subprocess (mere aggregation — the extension invokes
it at arm's length and does not link against it):

| Component | Purpose | License | Source |
|-----------|---------|---------|--------|
| **sqlmap** | The SQL injection tool that performs all detection/exploitation | GNU GPL v2.0 | https://github.com/sqlmapproject/sqlmap |
| **CPython (Windows embeddable)** | Interpreter used to run sqlmap without a system Python install | PSF License | https://www.python.org/ |

The complete, unmodified source of **sqlmap** is included inside the jar
(`runtime/sqlmap.zip`) as required by the GPL. sqlmap is distributed under the
GPL v2.0; a copy of that license is contained within the sqlmap archive.

Used only for the local test target (`test/VulnServer.java`), not bundled in the
extension jar:

| Component | License | Source |
|-----------|---------|--------|
| **sqlite-jdbc** (org.xerial) | Apache License 2.0 | https://github.com/xerial/sqlite-jdbc |
| **SLF4J API** | MIT License | https://www.slf4j.org/ |

Compile-time only (provided by Burp at runtime, not redistributed):

| Component | License | Source |
|-----------|---------|--------|
| **Burp Montoya API** (net.portswigger.burp.extensions) | provided by PortSwigger via Maven Central | https://portswigger.net/burp/documentation/desktop/extensions |
