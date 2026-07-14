package burpsqlmap;

import burp.api.montoya.MontoyaApi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * User-configured locations of the Python interpreter and the sqlmap install.
 * Nothing is bundled in the jar — the analyst downloads sqlmap (and, if needed,
 * Python) themselves and points the extension at them here. Values persist
 * across Burp sessions via Montoya preferences.
 */
class SqlmapSettings {

    static final String SQLMAP_DOWNLOAD_URL = "https://github.com/sqlmapproject/sqlmap";

    private static final String KEY_PYTHON = "burpsqlmap.pythonPath";
    private static final String KEY_SQLMAP = "burpsqlmap.sqlmapPath";

    private final MontoyaApi api;

    SqlmapSettings(MontoyaApi api) {
        this.api = api;
    }

    // ---- raw persisted values -------------------------------------------------

    String pythonPath() {
        String v = api.persistence().preferences().getString(KEY_PYTHON);
        return v == null ? "" : v;
    }

    String sqlmapPath() {
        String v = api.persistence().preferences().getString(KEY_SQLMAP);
        return v == null ? "" : v;
    }

    void setPythonPath(String v) {
        api.persistence().preferences().setString(KEY_PYTHON, v == null ? "" : v.trim());
    }

    void setSqlmapPath(String v) {
        api.persistence().preferences().setString(KEY_SQLMAP, v == null ? "" : v.trim());
    }

    // ---- resolution -----------------------------------------------------------

    /**
     * The Python command to launch. If the user left it blank we fall back to
     * "python" on PATH (or "python3" if only that exists is left to the OS).
     */
    String resolvePython() {
        String p = pythonPath();
        return p.isEmpty() ? "python" : p;
    }

    /**
     * The sqlmap.py file to run, resolved from the configured path which may be
     * either the sqlmap.py file itself or the directory that contains it
     * (including a nested "sqlmap-master" folder from a GitHub zip). Returns
     * null if it cannot be located.
     */
    Path resolveSqlmapPy() {
        String s = sqlmapPath();
        if (s.isEmpty()) {
            return null;
        }
        Path p = Paths.get(s);
        if (Files.isRegularFile(p)) {
            return p;
        }
        if (Files.isDirectory(p)) {
            Path direct = p.resolve("sqlmap.py");
            if (Files.exists(direct)) {
                return direct;
            }
            // GitHub zip extracts to sqlmap-master/ (or sqlmap-<ref>/)
            try (var stream = Files.newDirectoryStream(p, "sqlmap*")) {
                for (Path child : stream) {
                    Path nested = child.resolve("sqlmap.py");
                    if (Files.exists(nested)) {
                        return nested;
                    }
                }
            } catch (Exception ignored) {
                // fall through
            }
        }
        return null;
    }

    boolean isConfigured() {
        return resolveSqlmapPy() != null;
    }
}
