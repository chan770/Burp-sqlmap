package burpsqlmap;

import burp.api.montoya.MontoyaApi;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Integration test for RuntimeBootstrap: loads the bundled python-embed.zip and
 * sqlmap.zip from the classpath (the real burp-sqlmap.jar), extracts them, then
 * launches the extracted python to run sqlmap --version. Proves the extension's
 * "zero-install" runtime works end to end from the packaged jar.
 *
 * Run with the built jar on the classpath so getResourceAsStream finds /runtime/*.
 */
public class BootstrapTest {

    public static void main(String[] args) throws Exception {
        // Point extraction at a clean temp dir for a deterministic test.
        Path tmp = Files.createTempDirectory("bootstrap-test-");
        System.setProperty("java.io.tmpdir", tmp.toString());

        MontoyaApi api = fakeApi();
        RuntimeBootstrap rt = new RuntimeBootstrap(api);

        System.out.println("[test] isReady (before) = " + rt.isReady());
        boolean ok = rt.ensureExtracted();
        System.out.println("[test] ensureExtracted   = " + ok);
        System.out.println("[test] pythonExe exists  = " + Files.exists(rt.pythonExe()));
        System.out.println("[test] sqlmap.py exists   = " + Files.exists(rt.sqlmapPy()));

        // Confirm the ._pth was removed (restores sys.path for sqlmap imports).
        Path pyDir = rt.pythonExe().getParent();
        long pth = Files.list(pyDir).filter(p -> p.getFileName().toString().endsWith("._pth")).count();
        System.out.println("[test] leftover ._pth     = " + pth + " (expect 0)");

        // Actually run the extracted runtime.
        ProcessBuilder pb = new ProcessBuilder(
                rt.pythonExe().toString(), rt.sqlmapPy().toString(), "--version");
        pb.redirectErrorStream(true);
        pb.environment().put("PYTHONUTF8", "1");
        Process p = pb.start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        int code = p.waitFor();
        System.out.println("[test] sqlmap --version   = '" + out + "' (exit " + code + ")");

        boolean pass = ok && Files.exists(rt.pythonExe()) && Files.exists(rt.sqlmapPy())
                && pth == 0 && !out.isBlank() && code == 0;
        System.out.println(pass ? "[test] RESULT: PASS" : "[test] RESULT: FAIL");
        System.exit(pass ? 0 : 1);
    }

    /** Minimal MontoyaApi proxy: only api.logging().logToOutput(...) is exercised. */
    private static MontoyaApi fakeApi() {
        InvocationHandler logging = (proxy, method, a) -> {
            if (method.getName().equals("logToOutput") && a != null && a.length > 0) {
                System.out.println("   [ext-log] " + a[0]);
            }
            return null;
        };
        Object loggingProxy = Proxy.newProxyInstance(
                BootstrapTest.class.getClassLoader(),
                new Class[]{burp.api.montoya.logging.Logging.class}, logging);

        InvocationHandler apiHandler = (proxy, method, a) -> {
            if (method.getName().equals("logging")) {
                return loggingProxy;
            }
            return null;
        };
        return (MontoyaApi) Proxy.newProxyInstance(
                BootstrapTest.class.getClassLoader(),
                new Class[]{MontoyaApi.class}, apiHandler);
    }
}
