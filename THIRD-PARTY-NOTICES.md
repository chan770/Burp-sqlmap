# Third-party notices

The Burp extension in this repository is licensed under the MIT License (see
`LICENSE`). **No third-party software is bundled or redistributed in the jar.**

- **sqlmap** and **Python** are supplied by the user at runtime — you download
  them yourself and point the extension at their paths in the settings. This
  repo does not contain or redistribute sqlmap (GPL v2.0,
  https://github.com/sqlmapproject/sqlmap) or Python (PSF,
  https://www.python.org/).

Bundled/committed in this repo, or used only for the local test target:

| Component | Purpose | License | Source |
|-----------|---------|---------|--------|
| **Burp Montoya API** (`lib/montoya-api.jar`) | Compile-time API; provided by Burp at runtime | provided by PortSwigger via Maven Central | https://portswigger.net/burp/documentation/desktop/extensions |
| **sqlite-jdbc** (org.xerial) | Backing store for `test/VulnServer.java` only (not committed) | Apache License 2.0 | https://github.com/xerial/sqlite-jdbc |
| **SLF4J API** | Logging for the test server only (not committed) | MIT License | https://www.slf4j.org/ |
