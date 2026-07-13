package burpsqlmap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One sqlmap "session" — a single request with its own options, live output and
 * report, shown as one renamable tab (Repeater-style). Multiple ScanPanels run
 * independently and concurrently.
 */
class ScanPanel {

    private final MontoyaApi api;
    private final SqlmapRunner runner;
    private final SqlmapTab container;

    private final JPanel root;
    private final HttpRequestEditor requestEditor;
    private final JTextArea outputArea = new JTextArea();
    private final List<String> outputLog = new ArrayList<>();

    private static final String DOCS_URL = "https://github.com/sqlmapproject/sqlmap/wiki/Usage";

    /** A labelled option whose value is passed to sqlmap. */
    private static final class Opt {
        final String label;
        final String value;
        Opt(String label, String value) { this.label = label; this.value = value; }
        @Override public String toString() { return label; }
    }

    private static final Opt[] TECHNIQUES = {
        new Opt("Default (all)", ""),
        new Opt("Boolean-based blind (B)", "B"),
        new Opt("Error-based (E)", "E"),
        new Opt("UNION query (U)", "U"),
        new Opt("Stacked queries (S)", "S"),
        new Opt("Time-based blind (T)", "T"),
        new Opt("Inline queries (Q)", "Q"),
        new Opt("All explicit (BEUSTQ)", "BEUSTQ"),
    };

    private static final Opt[] DBMS_LIST = {
        new Opt("Auto-detect", ""),
        new Opt("MySQL", "MySQL"),
        new Opt("MariaDB", "MariaDB"),
        new Opt("PostgreSQL", "PostgreSQL"),
        new Opt("Microsoft SQL Server", "Microsoft SQL Server"),
        new Opt("Oracle", "Oracle"),
        new Opt("SQLite", "SQLite"),
        new Opt("IBM DB2", "IBM DB2"),
        new Opt("Firebird", "Firebird"),
        new Opt("Sybase", "Sybase"),
        new Opt("SAP MaxDB", "SAP MaxDB"),
        new Opt("HSQLDB", "HSQLDB"),
        new Opt("H2", "H2"),
        new Opt("Informix", "Informix"),
        new Opt("Microsoft Access", "Microsoft Access"),
        new Opt("MemSQL", "MemSQL"),
        new Opt("TiDB", "TiDB"),
        new Opt("CockroachDB", "CockroachDB"),
        new Opt("Vertica", "Vertica"),
        new Opt("Presto", "Presto"),
        new Opt("Amazon Redshift", "Amazon Redshift"),
        new Opt("Apache Derby", "Apache Derby"),
        new Opt("Cubrid", "Cubrid"),
        new Opt("Virtuoso", "Virtuoso"),
    };

    private final JSpinner levelSpin = new JSpinner(new SpinnerNumberModel(1, 1, 5, 1));
    private final JSpinner riskSpin = new JSpinner(new SpinnerNumberModel(1, 1, 3, 1));
    private final JSpinner threadsSpin = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
    private final JComboBox<Opt> techniqueCombo = new JComboBox<>(TECHNIQUES);
    private final JComboBox<Opt> dbmsCombo = new JComboBox<>(DBMS_LIST);
    private final JTextField extraField = new JTextField("", 16);
    private final JCheckBox bannerBox = new JCheckBox("Banner / user / db / is-dba", true);
    private final JCheckBox enumBox = new JCheckBox("Enumerate (--dbs --tables)", true);
    private final JCheckBox dumpBox = new JCheckBox("Dump all (--dump-all)");

    private final JButton runBtn = new JButton("Run sqlmap");
    private final JButton cancelBtn = new JButton("Cancel");
    private final JButton reportBtn = new JButton("Save HTML report");
    private final JLabel status = new JLabel("Idle.");

    private final AtomicReference<Process> proc = new AtomicReference<>();
    private volatile int lastExit = Integer.MIN_VALUE;
    private volatile boolean running = false;

    ScanPanel(MontoyaApi api, SqlmapRunner runner, SqlmapTab container) {
        this.api = api;
        this.runner = runner;
        this.container = container;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.root = build();
    }

    JComponent getComponent() {
        return root;
    }

    void loadRequest(HttpRequest request) {
        // Called on the EDT (from the context-menu action). Set synchronously so
        // a follow-up startScan() sees the request immediately.
        requestEditor.setRequest(request);
    }

    private JPanel build() {
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setEditable(false);

        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        opts.add(new JLabel("Level:"));
        opts.add(levelSpin);
        opts.add(new JLabel("Risk:"));
        opts.add(riskSpin);
        opts.add(new JLabel("Threads:"));
        opts.add(threadsSpin);
        opts.add(new JLabel("Technique:"));
        techniqueCombo.setToolTipText("sqlmap --technique. Default lets sqlmap use all.");
        opts.add(techniqueCombo);
        opts.add(new JLabel("DBMS:"));
        dbmsCombo.setMaximumRowCount(16);
        dbmsCombo.setToolTipText("Optional back-end DBMS hint (sqlmap --dbms).");
        opts.add(dbmsCombo);

        JPanel opts2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        opts2.add(bannerBox);
        opts2.add(enumBox);
        opts2.add(dumpBox);
        opts2.add(new JLabel("Extra args:"));
        extraField.setToolTipText("Space-separated raw sqlmap args, e.g. -p id --tamper=space2comment");
        opts2.add(extraField);
        opts2.add(docsLink());

        JPanel optsWrap = new JPanel();
        optsWrap.setLayout(new BoxLayout(optsWrap, BoxLayout.Y_AXIS));
        optsWrap.add(opts);
        optsWrap.add(opts2);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        cancelBtn.setEnabled(false);
        reportBtn.setEnabled(false);
        // Match Repeater's orange "Send" button.
        runBtn.putClientProperty("FlatLaf.style", "background: #ff6633; foreground: #ffffff");
        runBtn.setBackground(new Color(0xFF, 0x66, 0x33));
        runBtn.setForeground(Color.WHITE);
        buttons.add(runBtn);
        buttons.add(cancelBtn);
        buttons.add(reportBtn);
        buttons.add(status);

        runBtn.addActionListener(e -> startScan());
        cancelBtn.addActionListener(e -> cancel());
        reportBtn.addActionListener(e -> saveReport());

        JPanel top = new JPanel(new BorderLayout());
        top.add(optsWrap, BorderLayout.NORTH);
        top.add(buttons, BorderLayout.SOUTH);

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(BorderFactory.createTitledBorder("Target request (sent to sqlmap via -r)"));
        reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JScrollPane outScroll = new JScrollPane(outputArea);
        outScroll.setBorder(BorderFactory.createTitledBorder("sqlmap output"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqPanel, outScroll);
        split.setResizeWeight(0.35);

        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(top, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    /** A clickable link to sqlmap's official usage documentation. */
    private JLabel docsLink() {
        JLabel link = new JLabel("sqlmap docs ↗");
        link.setForeground(new Color(0x4a, 0x9e, 0xff));
        link.setToolTipText(DOCS_URL);
        link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        link.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new java.net.URI(DOCS_URL));
                } catch (Exception ex) {
                    api.logging().logToError("[docs] Could not open " + DOCS_URL + ": " + ex.getMessage());
                }
            }
        });
        return link;
    }

    void startScan() {
        if (running) {
            status.setText("A scan is already running in this tab.");
            return;
        }
        HttpRequest request = requestEditor.getRequest();
        if (request == null || request.toByteArray().length() == 0) {
            status.setText("No request. Right-click a request > 'Send request to sqlmap tab' first.");
            return;
        }
        if (request.httpService() == null) {
            status.setText("Request has no target host — send it from a real request in Burp.");
            return;
        }

        ScanOptions opts = collectOptions();
        outputLog.clear();
        outputArea.setText("");
        lastExit = Integer.MIN_VALUE;
        setRunning(true);

        final HttpRequest req = request;
        Thread worker = new Thread(() -> {
            int exit = runner.run(req, opts, this::appendLine, proc::set);
            ScanResultParser.Summary s = ScanResultParser.parse(outputLog);
            // Register a native Burp audit issue (off the EDT — it makes a
            // network request) so the finding shows under Target > Issues and
            // is included in Burp issue exports.
            if (s.vulnerable) {
                IssueReporter.report(api, req, s);
            }
            SwingUtilities.invokeLater(() -> {
                lastExit = exit;
                proc.set(null);
                setRunning(false);
                reportBtn.setEnabled(true);
                status.setText(s.vulnerable
                        ? "VULNERABLE — " + s.injectionPoints.size() + " injection point(s) found."
                        : "Finished — no injection confirmed (exit " + exit + ").");
                if (s.vulnerable) {
                    container.markVulnerable(this, req, s);
                }
            });
        }, "sqlmap-scan");
        worker.setDaemon(true);
        worker.start();
    }

    private void cancel() {
        SqlmapRunner.destroyTree(proc.get());
        status.setText("Cancelling...");
    }

    /** Kill this tab's scan if the tab is closed. */
    void dispose() {
        SqlmapRunner.destroyTree(proc.get());
    }

    private ScanOptions collectOptions() {
        ScanOptions o = new ScanOptions();
        o.level = (Integer) levelSpin.getValue();
        o.risk = (Integer) riskSpin.getValue();
        o.threads = (Integer) threadsSpin.getValue();
        o.technique = ((Opt) techniqueCombo.getSelectedItem()).value;
        o.dbms = ((Opt) dbmsCombo.getSelectedItem()).value;
        o.getBanner = bannerBox.isSelected();
        o.enumerate = enumBox.isSelected();
        o.dumpAll = dumpBox.isSelected();
        String extra = extraField.getText().trim();
        if (!extra.isEmpty()) {
            for (String tok : extra.split("\\s+")) {
                o.extraArgs.add(tok);
            }
        }
        return o;
    }

    private void appendLine(String line) {
        synchronized (outputLog) {
            outputLog.add(line);
        }
        SwingUtilities.invokeLater(() -> {
            outputArea.append(line + "\n");
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }

    private void setRunning(boolean run) {
        running = run;
        runBtn.setEnabled(!run);
        cancelBtn.setEnabled(run);
        if (run) {
            status.setText("Running sqlmap...");
        }
    }

    private void saveReport() {
        ScanResultParser.Summary summary = ScanResultParser.parse(outputLog);
        HttpRequest request = requestEditor.getRequest();
        String html = ReportGenerator.generate(request, summary, outputLog, lastExit);

        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        String defaultName = "sqlmap-report-" + stamp + ".html";

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(System.getProperty("user.home"), defaultName));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Path out = chooser.getSelectedFile().toPath();
            Files.writeString(out, html);
            status.setText("Report saved: " + out);
            api.logging().logToOutput("[report] " + out);
        } catch (Exception e) {
            status.setText("Failed to save report: " + e.getMessage());
        }
    }
}
