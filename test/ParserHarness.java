import burpsqlmap.ScanResultParser;
import burpsqlmap.ReportGenerator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Offline harness: feeds a captured sqlmap output file through the extension's
 * parser + report generator (no Burp required) to validate the reporting path
 * and emit docs/sample-report.html.
 *
 * The extension classes are package-private, so this harness is compiled into
 * the burpsqlmap package via a shim. See build/verify step in README.
 */
public class ParserHarness {
    public static void main(String[] args) throws Exception {
        Path in = Path.of(args[0]);
        Path out = Path.of(args.length > 1 ? args[1] : "docs/sample-report.html");
        List<String> lines = Files.readAllLines(in);

        ScanResultParser.Summary s = ScanResultParser.parse(lines);
        System.out.println("vulnerable      = " + s.vulnerable);
        System.out.println("dbms            = " + s.dbms);
        System.out.println("banner          = " + s.banner);
        System.out.println("injectionPoints = " + s.injectionPoints.size());
        for (ScanResultParser.Injection i : s.injectionPoints) {
            System.out.println("   - [" + i.type + "] " + i.parameter + " :: " + i.title);
        }
        System.out.println("databases       = " + s.databases);

        String html = ReportGenerator.generate(null, s, lines, 0);
        Files.createDirectories(out.getParent());
        Files.writeString(out, html);
        System.out.println("report written  = " + out + " (" + html.length() + " bytes)");
    }
}
