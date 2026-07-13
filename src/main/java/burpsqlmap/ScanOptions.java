package burpsqlmap;

import java.util.ArrayList;
import java.util.List;

/** Simple holder for the sqlmap scan configuration chosen in the UI. */
class ScanOptions {
    int level = 1;          // --level 1..5
    int risk = 1;           // --risk 1..3
    int threads = 1;        // --threads
    String technique = "";  // e.g. "BEUSTQ"; empty = sqlmap default
    String dbms = "";       // optional hint, e.g. "sqlite", "mysql"

    boolean getBanner = false;  // --banner --current-user --current-db --is-dba
    boolean enumerate = false;  // --dbs --tables
    boolean dumpAll = false;    // --dump-all

    List<String> extraArgs = new ArrayList<>();
}
