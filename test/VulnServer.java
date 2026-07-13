import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Intentionally-vulnerable demo web server for testing the Standalone sqlmap
 * Burp extension. Backed by a real in-memory SQLite database (sqlite-jdbc) so
 * that sqlmap detects genuine boolean/UNION/error/time-based injection.
 *
 *   GET /product?id=1     -> string-concatenated query: classic SQLi
 *
 * DO NOT deploy. For local testing only.
 *
 * Compile: javac -cp lib/sqlite-jdbc.jar test/VulnServer.java -d build/test
 * Run:     java  -cp "build/test;lib/sqlite-jdbc.jar;lib/slf4j-api.jar" VulnServer 8088
 */
public class VulnServer {

    private static Connection db;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8088;

        Class.forName("org.sqlite.JDBC");
        db = DriverManager.getConnection("jdbc:sqlite::memory:");
        seed();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/product", VulnServer::handleProduct);
        server.createContext("/", VulnServer::handleIndex);
        server.setExecutor(null);
        server.start();
        System.out.println("[VulnServer] listening on http://127.0.0.1:" + port);
        System.out.println("[VulnServer] try: http://127.0.0.1:" + port + "/product?id=1");
    }

    private static void seed() throws SQLException {
        try (Statement st = db.createStatement()) {
            st.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)");
            st.execute("INSERT INTO users VALUES (1,'admin','s3cr3t_admin_pw','admin@example.com')");
            st.execute("INSERT INTO users VALUES (2,'alice','alice_pw_2024','alice@example.com')");
            st.execute("INSERT INTO users VALUES (3,'bob','hunter2','bob@example.com')");

            st.execute("CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price TEXT)");
            st.execute("INSERT INTO products VALUES (1,'Widget','9.99')");
            st.execute("INSERT INTO products VALUES (2,'Gadget','19.99')");
            st.execute("INSERT INTO products VALUES (3,'Gizmo','29.99')");
        }
    }

    private static void handleIndex(HttpExchange ex) throws IOException {
        send(ex, 200, "<h1>Vulnerable demo</h1><p>Try <a href=\"/product?id=1\">/product?id=1</a></p>");
    }

    /** Classic SQL injection: user-controlled `id` concatenated into the SQL. */
    private static void handleProduct(HttpExchange ex) throws IOException {
        Map<String, String> q = query(ex.getRequestURI().getRawQuery());
        String id = q.getOrDefault("id", "1");

        // VULNERABLE ON PURPOSE — never do this in real code.
        String sql = "SELECT id, name, price FROM products WHERE id = " + id;

        StringBuilder body = new StringBuilder("<h1>Product lookup</h1>");
        try (Statement st = db.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            boolean any = false;
            body.append("<ul>");
            while (rs.next()) {
                any = true;
                body.append("<li>#").append(rs.getString(1))
                    .append(" — ").append(rs.getString(2))
                    .append(" ($").append(rs.getString(3)).append(")</li>");
            }
            body.append("</ul>");
            if (!any) {
                body.append("<p>No such product.</p>");
            }
            send(ex, 200, body.toString());
        } catch (SQLException e) {
            // Reflect the DB error (error-based injection surface).
            send(ex, 500, "<h1>Database error</h1><pre>" + e.getMessage() + "</pre>");
        }
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> m = new LinkedHashMap<>();
        if (raw == null) return m;
        for (String pair : raw.split("&")) {
            int i = pair.indexOf('=');
            if (i >= 0) {
                m.put(urlDecode(pair.substring(0, i)), urlDecode(pair.substring(i + 1)));
            }
        }
        return m;
    }

    private static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static void send(HttpExchange ex, int code, String html) throws IOException {
        byte[] b = ("<!doctype html><meta charset=utf-8>" + html).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
