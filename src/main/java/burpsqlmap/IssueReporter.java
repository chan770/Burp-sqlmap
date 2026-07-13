package burpsqlmap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Collections;

/**
 * Publishes a confirmed sqlmap finding as a native Burp audit issue via the
 * site map. Once added, the finding appears under Target &gt; Issues and is
 * included whenever the user exports Burp issues (HTML/XML), alongside Burp's
 * own findings.
 */
class IssueReporter {

    private static final String NAME = "SQL injection (confirmed by sqlmap)";

    static void report(MontoyaApi api, HttpRequest request, ScanResultParser.Summary summary) {
        if (request == null || !summary.vulnerable) {
            return;
        }
        try {
            String baseUrl = request.url() != null ? request.url() : "";

            // Avoid duplicates: if we already reported this endpoint (e.g. the
            // request was re-scanned), don't add a second copy. Burp normalises
            // baseUrl (dropping the query string), so compare on the query-less
            // endpoint rather than the full URL.
            String key = stripQuery(baseUrl);
            for (AuditIssue existing : api.siteMap().issues()) {
                if (NAME.equals(existing.name()) && key.equals(stripQuery(existing.baseUrl()))) {
                    api.logging().logToOutput("[issue] Already reported for " + key
                            + " — skipping duplicate.");
                    return;
                }
            }

            HttpRequestResponse evidence = evidenceFor(api, request);

            AuditIssue issue = AuditIssue.auditIssue(
                    NAME,
                    detail(summary),
                    remediation(),
                    baseUrl,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    background(),
                    remediationBackground(),
                    AuditIssueSeverity.HIGH,
                    Collections.singletonList(evidence));

            api.siteMap().add(issue);
            api.logging().logToOutput("[issue] Added Burp audit issue for " + baseUrl
                    + " (" + summary.injectionPoints.size() + " technique(s)).");
        } catch (Exception e) {
            api.logging().logToError("[issue] Failed to add audit issue: " + e.getMessage());
        }
    }

    /** Prefer a live request/response as evidence; fall back to the request alone. */
    private static HttpRequestResponse evidenceFor(MontoyaApi api, HttpRequest request) {
        try {
            HttpRequestResponse rr = api.http().sendRequest(request);
            if (rr != null && rr.response() != null) {
                return rr;
            }
        } catch (Exception ignored) {
            // network may be unavailable; fall through
        }
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private static String detail(ScanResultParser.Summary s) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p><b>sqlmap</b> confirmed one or more SQL injection points in this request.</p>");
        if (!s.dbms.isEmpty()) {
            sb.append("<p><b>Back-end DBMS:</b> ").append(esc(s.dbms));
            if (!s.banner.isEmpty()) {
                sb.append(" (banner: ").append(esc(s.banner)).append(")");
            }
            sb.append("</p>");
        }
        if (!s.injectionPoints.isEmpty()) {
            sb.append("<p><b>Injection points:</b></p><ul>");
            for (ScanResultParser.Injection inj : s.injectionPoints) {
                sb.append("<li><b>").append(esc(inj.parameter)).append("</b> &mdash; ")
                  .append(esc(inj.type));
                if (!inj.title.isEmpty()) {
                    sb.append(" <i>(").append(esc(inj.title)).append(")</i>");
                }
                sb.append("</li>");
            }
            sb.append("</ul>");
        }
        if (!s.databases.isEmpty()) {
            sb.append("<p><b>Databases discovered:</b> ")
              .append(esc(String.join(", ", s.databases))).append("</p>");
        }
        if (!s.tables.isEmpty()) {
            sb.append("<p><b>Tables enumerated:</b></p><ul>");
            for (String table : s.tables) {
                sb.append("<li>").append(esc(table)).append("</li>");
            }
            sb.append("</ul>");
        }
        sb.append("<p>Reported by the Standalone sqlmap extension.</p>");
        return sb.toString();
    }

    private static String remediation() {
        return "<p>Use parameterised queries (prepared statements) for all database access. "
                + "Validate and canonicalise input, apply least-privilege database accounts, and "
                + "avoid building SQL by string concatenation.</p>";
    }

    private static String background() {
        return "<p>SQL injection lets an attacker interfere with the queries an application makes "
                + "to its database, potentially reading or modifying data, or in some cases "
                + "executing operating-system commands. This issue was verified dynamically by "
                + "sqlmap, so it is a confirmed (not speculative) finding.</p>";
    }

    private static String remediationBackground() {
        return "<p>Parameterised queries ensure user input is always treated as data, never as "
                + "executable SQL, which eliminates the injection vector regardless of input content.</p>";
    }

    private static String stripQuery(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
