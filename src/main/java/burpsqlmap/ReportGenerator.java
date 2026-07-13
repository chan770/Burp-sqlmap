package burpsqlmap;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Renders a self-contained HTML report from a scan summary and raw output. */
public class ReportGenerator {

    public static String generate(HttpRequest request, ScanResultParser.Summary s,
                           List<String> outputLog, int exitCode) {
        String when = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String target = request != null && request.url() != null ? request.url() : "(unknown)";

        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.append("<title>sqlmap report</title><style>");
        sb.append("body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}");
        sb.append(".wrap{max-width:1000px;margin:0 auto;padding:24px}");
        sb.append("h1{font-size:22px;margin:0 0 4px} .sub{color:#8a93a2;margin:0 0 20px}");
        sb.append(".badge{display:inline-block;padding:4px 12px;border-radius:14px;font-weight:600;font-size:13px}");
        sb.append(".vuln{background:#3a1113;color:#ff8a8a;border:1px solid #7a1f24}");
        sb.append(".clean{background:#0f2a17;color:#6ee7a0;border:1px solid #1f6a3a}");
        sb.append("table{border-collapse:collapse;width:100%;margin:12px 0}");
        sb.append("th,td{border:1px solid #262b35;padding:8px 10px;text-align:left;font-size:13px;vertical-align:top}");
        sb.append("th{background:#1a1f28;color:#b8c1cf}");
        sb.append("h2{font-size:16px;margin:24px 0 8px;border-bottom:1px solid #262b35;padding-bottom:6px}");
        sb.append("pre{background:#0a0c10;border:1px solid #262b35;border-radius:6px;padding:12px;overflow:auto;");
        sb.append("font-size:12px;line-height:1.4;max-height:520px}");
        sb.append(".k{color:#8a93a2}");
        sb.append("</style></head><body><div class=\"wrap\">");

        sb.append("<h1>Standalone sqlmap — scan report</h1>");
        sb.append("<p class=\"sub\">Generated ").append(esc(when)).append("</p>");

        sb.append(s.vulnerable
                ? "<span class=\"badge vuln\">SQL INJECTION CONFIRMED</span>"
                : "<span class=\"badge clean\">No injection confirmed</span>");

        sb.append("<h2>Target</h2><table>");
        row(sb, "URL", target);
        row(sb, "Method", request != null ? request.method() : "");
        row(sb, "Back-end DBMS", s.dbms.isEmpty() ? "—" : s.dbms);
        if (!s.banner.isEmpty()) row(sb, "Banner", s.banner);
        row(sb, "sqlmap exit code", String.valueOf(exitCode));
        sb.append("</table>");

        if (!s.injectionPoints.isEmpty()) {
            sb.append("<h2>Injection points</h2><table>");
            sb.append("<tr><th>Parameter</th><th>Type</th><th>Title</th></tr>");
            for (ScanResultParser.Injection inj : s.injectionPoints) {
                sb.append("<tr><td>").append(esc(inj.parameter)).append("</td><td>")
                  .append(esc(inj.type)).append("</td><td>").append(esc(inj.title))
                  .append("</td></tr>");
            }
            sb.append("</table>");
        }

        if (!s.databases.isEmpty()) {
            sb.append("<h2>Databases discovered</h2><table>");
            for (String db : s.databases) {
                sb.append("<tr><td>").append(esc(db)).append("</td></tr>");
            }
            sb.append("</table>");
        }

        if (!s.tables.isEmpty()) {
            sb.append("<h2>Tables enumerated</h2><table>");
            for (String table : s.tables) {
                sb.append("<tr><td>").append(esc(table)).append("</td></tr>");
            }
            sb.append("</table>");
        }

        if (!s.dumpedTables.isEmpty()) {
            sb.append("<h2>Dumped data</h2>");
            for (ScanResultParser.DumpedTable dt : s.dumpedTables) {
                sb.append("<h3 style=\"margin:16px 0 4px\">Table: ").append(esc(dt.name)).append("</h3><pre>");
                for (String l : dt.lines) {
                    sb.append(esc(l)).append("\n");
                }
                sb.append("</pre>");
            }
        }

        sb.append("<h2>Full sqlmap output</h2><pre>");
        for (String line : outputLog) {
            sb.append(esc(line)).append("\n");
        }
        sb.append("</pre>");

        sb.append("<p class=\"k\">Produced by the Standalone sqlmap Burp extension. ")
          .append("sqlmap is the source of truth for all findings above.</p>");
        sb.append("</div></body></html>");
        return sb.toString();
    }

    private static void row(StringBuilder sb, String k, String v) {
        sb.append("<tr><th style=\"width:180px\">").append(esc(k)).append("</th><td>")
          .append(esc(v == null ? "" : v)).append("</td></tr>");
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
