package burpsqlmap;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Best-effort extraction of the interesting facts from sqlmap's console output:
 * whether anything was found vulnerable, which parameters/techniques, and the
 * back-end DBMS. Purely presentational — sqlmap itself is the source of truth.
 */
public class ScanResultParser {

    public static class Injection {
        public String parameter = "";
        public String type = "";
        public String title = "";
    }

    /** A table's dumped contents (the ASCII box sqlmap prints for --dump). */
    public static class DumpedTable {
        public String name = "";
        public List<String> lines = new ArrayList<>();
    }

    public static class Summary {
        public boolean vulnerable = false;
        public String dbms = "";
        public String banner = "";
        public List<Injection> injectionPoints = new ArrayList<>();
        public List<String> databases = new ArrayList<>();
        /** Table names sqlmap enumerated, formatted "database.table" when the db is known. */
        public List<String> tables = new ArrayList<>();
        /** Dumped table contents (populated when --dump / --dump-all is used). */
        public List<DumpedTable> dumpedTables = new ArrayList<>();
    }

    private static final Pattern PARAM =
            Pattern.compile("Parameter:\\s*(.+?)\\s*\\((\\w+)\\)");
    private static final Pattern TYPE = Pattern.compile("^\\s*Type:\\s*(.+)$");
    private static final Pattern TITLE = Pattern.compile("^\\s*Title:\\s*(.+)$");
    private static final Pattern DBMS =
            Pattern.compile("back-end DBMS:\\s*(.+)$");
    private static final Pattern BANNER =
            Pattern.compile("banner:\\s*'(.+?)'");
    // "fetching tables for database: 'foo'"  or  "Database: foo"
    private static final Pattern TABLE_DB =
            Pattern.compile("(?:fetching tables for database:\\s*'(.+?)'|^Database:\\s*(.+?)\\s*$)");
    private static final Pattern TABLE_HEADER =
            Pattern.compile("^\\[\\d+\\s+tables?\\]$");
    // A single-column table-listing row like "| products |"
    private static final Pattern TABLE_ROW =
            Pattern.compile("^\\|\\s*([^|]+?)\\s*\\|$");
    // Dump output: "Table: users" then "[3 entries]" then an ASCII box.
    private static final Pattern DUMP_TABLE = Pattern.compile("^Table:\\s*(.+?)\\s*$");
    private static final Pattern DUMP_ENTRIES = Pattern.compile("^\\[\\d+\\s+entr(?:ies|y)\\]$");

    public static Summary parse(List<String> lines) {
        Summary s = new Summary();
        String currentParameter = "";
        Injection cur = null;
        boolean inDatabasesSection = false;
        boolean inTablesSection = false;
        String tableDb = "";
        String dumpName = "";
        DumpedTable curDump = null;
        boolean inDumpBox = false;

        for (String line : lines) {
            if (line.contains("is vulnerable") ||
                line.contains("sqlmap identified the following injection point")) {
                s.vulnerable = true;
            }

            Matcher mParam = PARAM.matcher(line);
            if (mParam.find()) {
                currentParameter = mParam.group(1).trim();
                s.vulnerable = true;
                cur = null;
                continue;
            }
            // A parameter can be injectable via several techniques; sqlmap
            // prints one "Type:"/"Title:" pair per technique — one entry each.
            Matcher mType = TYPE.matcher(line);
            if (mType.find()) {
                cur = new Injection();
                cur.parameter = currentParameter;
                cur.type = mType.group(1).trim();
                s.injectionPoints.add(cur);
                continue;
            }
            Matcher mTitle = TITLE.matcher(line);
            if (cur != null && mTitle.find()) {
                cur.title = mTitle.group(1).trim();
                continue;
            }
            Matcher mDbms = DBMS.matcher(line);
            if (mDbms.find() && s.dbms.isEmpty()) {
                s.dbms = mDbms.group(1).trim();
            }
            Matcher mBanner = BANNER.matcher(line);
            if (mBanner.find() && s.banner.isEmpty()) {
                s.banner = mBanner.group(1).trim();
            }

            // "available databases [N]:" followed by "[*] name" lines.
            String t = line.trim();
            if (t.matches("(?i)available databases \\[\\d+\\]:")) {
                inDatabasesSection = true;
                continue;
            }
            if (inDatabasesSection) {
                if (t.startsWith("[*] ")) {
                    s.databases.add(t.substring(4).trim());
                } else if (!t.isEmpty()) {
                    inDatabasesSection = false;
                }
            }

            // Track which database the upcoming table box belongs to.
            Matcher mTableDb = TABLE_DB.matcher(t);
            if (mTableDb.find()) {
                tableDb = mTableDb.group(1) != null ? mTableDb.group(1).trim()
                        : (mTableDb.group(2) != null ? mTableDb.group(2).trim() : "");
            }
            // "[N tables]" opens a box of "| name |" rows; a "+---+" or blank closes it.
            if (TABLE_HEADER.matcher(t).matches()) {
                inTablesSection = true;
                continue;
            }
            if (inTablesSection) {
                if (t.startsWith("+") || t.isEmpty() || t.equals("<current>")) {
                    if (t.startsWith("+") && !s.tables.isEmpty()) {
                        // trailing box border after rows ends the section
                        inTablesSection = false;
                    }
                    continue;
                }
                Matcher mRow = TABLE_ROW.matcher(t);
                if (mRow.matches()) {
                    String name = mRow.group(1).trim();
                    // Drop sqlmap's placeholder database names (e.g. "<current>",
                    // "SQLite_masterdb") so table names read cleanly. Keep a real
                    // database name as a prefix for multi-DB engines (MySQL etc.).
                    boolean placeholderDb = tableDb.isEmpty()
                            || tableDb.equalsIgnoreCase("<current>")
                            || tableDb.equalsIgnoreCase("SQLite")
                            || tableDb.toLowerCase().contains("masterdb");
                    s.tables.add(placeholderDb ? name : tableDb + "." + name);
                } else {
                    inTablesSection = false;
                }
            }

            // ---- dumped table data (--dump / --dump-all) ----
            Matcher mDump = DUMP_TABLE.matcher(t);
            if (mDump.matches()) {
                dumpName = mDump.group(1).trim();
                inDumpBox = false;
                continue;
            }
            if (DUMP_ENTRIES.matcher(t).matches()) {
                curDump = new DumpedTable();
                curDump.name = dumpName;
                s.dumpedTables.add(curDump);
                if (!dumpName.isEmpty() && !s.tables.contains(dumpName)) {
                    s.tables.add(dumpName); // so table names show even under --dump-all
                }
                inDumpBox = true;
                continue;
            }
            if (inDumpBox && curDump != null) {
                if (t.startsWith("+") || t.startsWith("|")) {
                    curDump.lines.add(line);
                } else if (!t.isEmpty()) {
                    inDumpBox = false;
                }
            }
        }
        return s;
    }
}
