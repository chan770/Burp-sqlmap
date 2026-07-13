package burpsqlmap;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Extracts the bundled Python runtime and sqlmap source from the extension JAR
 * to a stable per-user temp directory, exactly once. After extraction the
 * embeddable Python's ._pth file is removed so that Python restores its normal
 * sys.path resolution (which is required for sqlmap's relative package imports).
 */
class RuntimeBootstrap {

    private static final String VERSION = "1"; // bump to force re-extraction
    private static final String PY_ZIP = "/runtime/python-embed.zip";
    private static final String SQLMAP_ZIP = "/runtime/sqlmap.zip";

    private final MontoyaApi api;
    private final Path baseDir;

    RuntimeBootstrap(MontoyaApi api) {
        this.api = api;
        String tmp = System.getProperty("java.io.tmpdir", ".");
        this.baseDir = Paths.get(tmp, "burp-sqlmap-runtime", VERSION);
    }

    /** Location where sqlmap.py can be found once ready. */
    Path pythonExe() {
        return baseDir.resolve("py").resolve("python.exe");
    }

    Path sqlmapPy() {
        // sqlmap zip extracts as sqlmap-master/sqlmap.py
        Path direct = baseDir.resolve("sqlmap").resolve("sqlmap.py");
        if (Files.exists(direct)) {
            return direct;
        }
        Path master = baseDir.resolve("sqlmap").resolve("sqlmap-master").resolve("sqlmap.py");
        return master;
    }

    boolean isReady() {
        return Files.exists(pythonExe()) && Files.exists(sqlmapPy());
    }

    /** Extract bundled runtime if not already present. Returns true when ready. */
    synchronized boolean ensureExtracted() {
        if (isReady()) {
            return true;
        }
        try {
            log("Extracting bundled runtime to " + baseDir + " (first run only)...");
            Files.createDirectories(baseDir);

            Path pyDir = baseDir.resolve("py");
            Path sqlmapDir = baseDir.resolve("sqlmap");

            extractResourceZip(PY_ZIP, pyDir);
            extractResourceZip(SQLMAP_ZIP, sqlmapDir);

            // Embeddable Python ships a ._pth that suppresses adding the script
            // directory to sys.path; removing it restores normal behavior so
            // sqlmap's `import lib.utils.versioncheck` works.
            removePthFiles(pyDir);

            boolean ok = isReady();
            log(ok ? "Runtime ready." : "Runtime extraction incomplete.");
            return ok;
        } catch (IOException e) {
            log("ERROR extracting runtime: " + e.getMessage());
            return false;
        }
    }

    private void removePthFiles(Path pyDir) throws IOException {
        if (!Files.isDirectory(pyDir)) {
            return;
        }
        try (var stream = Files.newDirectoryStream(pyDir, "*._pth")) {
            for (Path p : stream) {
                Files.deleteIfExists(p);
                log("Removed " + p.getFileName() + " to restore sys.path.");
            }
        }
    }

    private void extractResourceZip(String resource, Path targetDir) throws IOException {
        Files.createDirectories(targetDir);
        try (InputStream in = SqlmapExtension.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Bundled resource not found: " + resource
                        + " — did the build embed src/main/resources?");
            }
            try (ZipInputStream zis = new ZipInputStream(in)) {
                ZipEntry entry;
                byte[] buf = new byte[8192];
                while ((entry = zis.getNextEntry()) != null) {
                    Path out = safeResolve(targetDir, entry.getName());
                    if (entry.isDirectory()) {
                        Files.createDirectories(out);
                    } else {
                        Files.createDirectories(out.getParent());
                        try (var os = Files.newOutputStream(out)) {
                            int n;
                            while ((n = zis.read(buf)) > 0) {
                                os.write(buf, 0, n);
                            }
                        }
                    }
                    zis.closeEntry();
                }
            }
        }
    }

    /** Guard against Zip Slip. */
    private Path safeResolve(Path dir, String name) throws IOException {
        Path resolved = dir.resolve(name).normalize();
        if (!resolved.startsWith(dir.normalize())) {
            throw new IOException("Blocked unsafe zip entry: " + name);
        }
        return resolved;
    }

    private void log(String msg) {
        api.logging().logToOutput("[runtime] " + msg);
    }
}
