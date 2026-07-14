package burpsqlmap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Executes a user-supplied sqlmap as a subprocess, using the Python and sqlmap
 * locations configured in {@link SqlmapSettings}. A Burp request is written to a
 * temporary raw-request file and passed to sqlmap via -r so the exact
 * headers/cookies/body are used. Supports multiple concurrent scans (one per UI
 * tab); each scan's process is reported to the caller via {@code onStart} so the
 * caller can cancel just that scan.
 */
class SqlmapRunner {

    private final MontoyaApi api;
    private final SqlmapSettings settings;
    private final Set<Process> active = ConcurrentHashMap.newKeySet();

    SqlmapRunner(MontoyaApi api, SqlmapSettings settings) {
        this.api = api;
        this.settings = settings;
    }

    /** Kill every running scan; used on extension unload. */
    void shutdown() {
        for (Process p : active) {
            destroyTree(p);
        }
    }

    static void destroyTree(Process p) {
        if (p != null && p.isAlive()) {
            p.descendants().forEach(ProcessHandle::destroy);
            p.destroy();
        }
    }

    /**
     * Run a scan. Blocks until sqlmap exits; intended to be called on a worker
     * thread. Output lines are delivered to {@code onLine}; the started Process
     * is delivered to {@code onStart} (so the caller can cancel it). Returns the
     * process exit code, or -1 if the runtime could not be prepared.
     */
    int run(HttpRequest request, ScanOptions opts, Consumer<String> onLine, Consumer<Process> onStart) {
        Path sqlmapPy = settings.resolveSqlmapPy();
        if (sqlmapPy == null) {
            onLine.accept("[!] sqlmap location is not set (or sqlmap.py was not found there).");
            onLine.accept("[!] Open the 'sqlmap configuration' bar at the top of this tab and set the");
            onLine.accept("    path to your sqlmap folder or sqlmap.py.");
            onLine.accept("[!] Download sqlmap from: " + SqlmapSettings.SQLMAP_DOWNLOAD_URL);
            return -1;
        }

        Path workDir;
        Path requestFile;
        Path outputDir;
        try {
            workDir = Files.createTempDirectory("sqlmap-scan-");
            requestFile = workDir.resolve("request.txt");
            outputDir = workDir.resolve("output");
            Files.createDirectories(outputDir);
            Files.write(requestFile, request.toByteArray().getBytes());
        } catch (IOException e) {
            onLine.accept("[!] Failed to stage request: " + e.getMessage());
            return -1;
        }

        List<String> cmd = buildCommand(request, sqlmapPy, requestFile, outputDir, opts);
        onLine.accept("[*] Python:  " + settings.resolvePython());
        onLine.accept("[*] sqlmap:  " + sqlmapPy);
        onLine.accept("[*] Command: " + String.join(" ", cmd));
        onLine.accept("");

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(sqlmapPy.getParent().toFile());
        pb.redirectErrorStream(true);
        // Ensure UTF-8 so sqlmap's banner/table drawing does not crash on cp1252.
        pb.environment().put("PYTHONIOENCODING", "utf-8");
        pb.environment().put("PYTHONUTF8", "1");

        int exit;
        Process proc = null;
        try {
            proc = pb.start();
            active.add(proc);
            if (onStart != null) {
                onStart.accept(proc);
            }
            // Close sqlmap's stdin immediately (EOF). Otherwise it detects a
            // non-tty pipe, assumes a targets list is arriving on STDIN, and
            // blocks forever instead of using our -r request file.
            try {
                proc.getOutputStream().close();
            } catch (IOException ignored) {
                // best effort
            }
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    onLine.accept(line);
                }
            }
            exit = proc.waitFor();
        } catch (IOException e) {
            onLine.accept("[!] Failed to launch sqlmap: " + e.getMessage());
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            onLine.accept("[!] Scan interrupted.");
            return -1;
        } finally {
            if (proc != null) {
                active.remove(proc);
            }
        }

        onLine.accept("");
        onLine.accept("[*] sqlmap finished with exit code " + exit);
        onLine.accept("[*] Full sqlmap output/session saved under: " + outputDir);
        return exit;
    }

    private List<String> buildCommand(HttpRequest request, Path sqlmapPy, Path requestFile, Path outputDir, ScanOptions opts) {
        List<String> cmd = new ArrayList<>();
        cmd.add(settings.resolvePython());
        cmd.add(sqlmapPy.toString());
        cmd.add("-r");
        cmd.add(requestFile.toString());

        // Non-interactive: never prompt for input.
        cmd.add("--batch");
        // Never treat our (non-tty) stdin pipe as a targets list — without this
        // sqlmap reads STDIN, finds it empty, and exits instead of using -r.
        cmd.add("--ignore-stdin");
        // Deterministic, machine-parseable output location.
        cmd.add("--output-dir=" + outputDir);
        cmd.add("--flush-session");
        cmd.add("--disable-coloring");

        if (request.httpService() != null && request.httpService().secure()) {
            cmd.add("--force-ssl");
        }

        cmd.add("--level=" + opts.level);
        cmd.add("--risk=" + opts.risk);

        if (opts.technique != null && !opts.technique.isBlank()) {
            cmd.add("--technique=" + opts.technique);
        }
        if (opts.threads > 1) {
            cmd.add("--threads=" + opts.threads);
        }
        if (opts.dbms != null && !opts.dbms.isBlank()) {
            cmd.add("--dbms=" + opts.dbms);
        }
        if (opts.dumpAll) {
            cmd.add("--dump-all");
        } else if (opts.enumerate) {
            cmd.add("--dbs");
            cmd.add("--tables");
        }
        if (opts.getBanner) {
            cmd.add("--banner");
            cmd.add("--current-user");
            cmd.add("--current-db");
            cmd.add("--is-dba");
        }
        for (String extra : opts.extraArgs) {
            if (!extra.isBlank()) {
                cmd.add(extra);
            }
        }
        return cmd;
    }
}
