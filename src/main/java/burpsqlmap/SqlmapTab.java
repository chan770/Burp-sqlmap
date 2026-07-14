package burpsqlmap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The suite tab. Hosts a Repeater-style JTabbedPane of {@link ScanPanel}s (one
 * renamable tab per request) and a left-hand "Vulnerable findings" panel: a list
 * of confirmed findings on top and, below, the details (injection points and
 * enumerated tables) of the selected finding.
 */
class SqlmapTab {

    private final MontoyaApi api;
    private final SqlmapRunner runner;
    private final SqlmapSettings settings;

    private final JTextField pythonField = new JTextField(22);
    private final JTextField sqlmapField = new JTextField(30);
    private final JLabel configStatus = new JLabel();

    private final JPanel root;
    private final JTabbedPane tabs = new JTabbedPane();
    private final JPanel plusPlaceholder = new JPanel(); // body of the "+" tab (never shown)
    private final DefaultListModel<VulnEntry> vulnModel = new DefaultListModel<>();
    private final JList<VulnEntry> vulnList = new JList<>(vulnModel);
    private final JTextArea detailArea = new JTextArea();
    private final Map<ScanPanel, VulnEntry> vulnByPanel = new LinkedHashMap<>();

    private int counter = 0;

    SqlmapTab(MontoyaApi api, SqlmapRunner runner, SqlmapSettings settings) {
        this.api = api;
        this.runner = runner;
        this.settings = settings;
        this.root = build();
        addBlankTab(); // start with one empty tab, like Repeater
    }

    Component getComponent() {
        return root;
    }

    private JPanel build() {
        // ---- left/top: list of findings ----
        vulnList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        vulnList.setFixedCellHeight(24);
        vulnList.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        vulnList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                VulnEntry sel = vulnList.getSelectedValue();
                if (sel != null) {
                    selectPanel(sel.panel);
                    detailArea.setText(renderDetail(sel));
                    detailArea.setCaretPosition(0);
                }
            }
        });
        JScrollPane listScroll = new JScrollPane(vulnList);
        listScroll.setBorder(BorderFactory.createTitledBorder("Vulnerable findings"));

        // ---- left/bottom: details of the selected finding ----
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(false); // keep dumped ASCII tables aligned
        detailArea.setText("Select a finding to see its injection points and tables.");
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Details"));

        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, listScroll, detailScroll);
        leftSplit.setResizeWeight(0.35);
        leftSplit.setDividerLocation(160);
        JPanel left = new JPanel(new BorderLayout());
        left.add(leftSplit, BorderLayout.CENTER);
        left.setPreferredSize(new Dimension(300, 100));

        // ---- right: tabs with a trailing "+" new-tab button ----
        // "+" button implemented as a small, always-last placeholder tab so it
        // sits directly after the last real tab (browser-style), not at the far
        // edge of the tab strip.
        JButton addBtn = new JButton("+");
        addBtn.setToolTipText("New scan tab (double-click a tab to rename it)");
        addBtn.setFocusable(false);
        addBtn.putClientProperty("FlatLaf.style",
                "background: #ff6633; foreground: #ffffff; focusWidth: 0; arc: 6");
        addBtn.setBackground(new Color(0xFF, 0x66, 0x33));
        addBtn.setForeground(Color.WHITE);
        addBtn.setFont(addBtn.getFont().deriveFont(Font.BOLD, 13f));
        addBtn.setMargin(new Insets(0, 0, 0, 0));
        Dimension sz = new Dimension(22, 20);
        addBtn.setPreferredSize(sz);
        addBtn.addActionListener(e -> addBlankTab());

        tabs.addTab("", plusPlaceholder);
        tabs.setTabComponentAt(tabs.indexOfComponent(plusPlaceholder), addBtn);
        // Never let the "+" placeholder tab become the active tab.
        tabs.addChangeListener(e -> {
            int i = tabs.getSelectedIndex();
            if (i >= 0 && tabs.getComponentAt(i) == plusPlaceholder) {
                int last = tabs.indexOfComponent(plusPlaceholder) - 1;
                if (last >= 0) {
                    tabs.setSelectedIndex(last);
                }
            }
        });

        JPanel right = new JPanel(new BorderLayout());
        right.add(tabs, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setResizeWeight(0.0);
        split.setDividerLocation(300);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(buildConfigBar(), BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    /** Top bar where the analyst points the extension at their Python + sqlmap. */
    private JComponent buildConfigBar() {
        pythonField.setText(settings.pythonPath());
        sqlmapField.setText(settings.sqlmapPath());
        pythonField.setToolTipText("Path to python/python3. Leave blank to use 'python' on PATH.");
        sqlmapField.setToolTipText("Path to your sqlmap folder or sqlmap.py.");

        JButton pyBrowse = new JButton("Browse…");
        pyBrowse.addActionListener(e -> browseInto(pythonField, false));
        JButton smBrowse = new JButton("Browse…");
        smBrowse.addActionListener(e -> browseInto(sqlmapField, true));

        JButton save = new JButton("Save");
        save.putClientProperty("FlatLaf.style", "background: #ff6633; foreground: #ffffff");
        save.setBackground(new Color(0xFF, 0x66, 0x33));
        save.setForeground(Color.WHITE);
        save.addActionListener(e -> saveConfig());

        JButton test = new JButton("Test");
        test.addActionListener(e -> testConfig());

        JLabel download = new JLabel("Download sqlmap ↗");
        download.setForeground(new Color(0x4a, 0x9e, 0xff));
        download.setToolTipText(SqlmapSettings.SQLMAP_DOWNLOAD_URL);
        download.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        download.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new java.net.URI(SqlmapSettings.SQLMAP_DOWNLOAD_URL));
                } catch (Exception ex) {
                    api.logging().logToError("[config] open failed: " + ex.getMessage());
                }
            }
        });

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        row.add(new JLabel("sqlmap:"));
        row.add(sqlmapField);
        row.add(smBrowse);
        row.add(new JLabel("   Python:"));
        row.add(pythonField);
        row.add(pyBrowse);
        row.add(save);
        row.add(test);
        row.add(download);

        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(BorderFactory.createTitledBorder("sqlmap configuration"));
        bar.add(row, BorderLayout.CENTER);
        configStatus.setBorder(BorderFactory.createEmptyBorder(0, 8, 4, 8));
        bar.add(configStatus, BorderLayout.SOUTH);
        refreshConfigStatus();
        return bar;
    }

    private void browseInto(JTextField field, boolean directoriesToo) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(directoriesToo
                ? JFileChooser.FILES_AND_DIRECTORIES : JFileChooser.FILES_ONLY);
        String cur = field.getText().trim();
        if (!cur.isEmpty()) {
            java.io.File f = new java.io.File(cur);
            chooser.setCurrentDirectory(f.isDirectory() ? f : f.getParentFile());
        }
        if (chooser.showOpenDialog(root) == JFileChooser.APPROVE_OPTION) {
            field.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void saveConfig() {
        settings.setPythonPath(pythonField.getText().trim());
        settings.setSqlmapPath(sqlmapField.getText().trim());
        refreshConfigStatus();
    }

    private void refreshConfigStatus() {
        java.nio.file.Path py = settings.resolveSqlmapPy();
        if (py != null) {
            configStatus.setText("✓ sqlmap found: " + py + "   |   Python: " + settings.resolvePython());
            configStatus.setForeground(new Color(0x4c, 0xaf, 0x50));
        } else {
            configStatus.setText("✗ Set the path to your sqlmap folder or sqlmap.py, then Save. "
                    + "Download it from " + SqlmapSettings.SQLMAP_DOWNLOAD_URL);
            configStatus.setForeground(new Color(0xE0, 0x5a, 0x5a));
        }
    }

    private void testConfig() {
        saveConfig();
        java.nio.file.Path sqlmapPy = settings.resolveSqlmapPy();
        if (sqlmapPy == null) {
            configStatus.setText("✗ sqlmap not found at that path.");
            configStatus.setForeground(new Color(0xE0, 0x5a, 0x5a));
            return;
        }
        configStatus.setText("Testing '" + settings.resolvePython() + " sqlmap.py --version' …");
        configStatus.setForeground(null);
        Thread t = new Thread(() -> {
            String result;
            try {
                ProcessBuilder pb = new ProcessBuilder(
                        settings.resolvePython(), sqlmapPy.toString(), "--version", "--batch");
                pb.redirectErrorStream(true);
                pb.environment().put("PYTHONIOENCODING", "utf-8");
                Process p = pb.start();
                p.getOutputStream().close();
                String out = new String(p.getInputStream().readAllBytes(),
                        java.nio.charset.StandardCharsets.UTF_8).trim();
                int code = p.waitFor();
                String version = out.lines().filter(l -> l.matches("^[0-9].*")).findFirst().orElse(out);
                result = code == 0 && !version.isBlank()
                        ? "✓ sqlmap works — version " + version
                        : "✗ sqlmap did not run cleanly (exit " + code + "): " + out;
            } catch (Exception ex) {
                result = "✗ Could not run sqlmap: " + ex.getMessage()
                        + "  (check the Python path)";
            }
            final String msg = result;
            SwingUtilities.invokeLater(() -> {
                configStatus.setText(msg);
                configStatus.setForeground(msg.startsWith("✓")
                        ? new Color(0x4c, 0xaf, 0x50) : new Color(0xE0, 0x5a, 0x5a));
            });
        }, "sqlmap-test");
        t.setDaemon(true);
        t.start();
    }

    /** Create a new empty tab (user then pastes/edits a request). */
    ScanPanel addBlankTab() {
        return addTab(null, "Scan " + (++counter));
    }

    /** Create a tab for a request; used by the context menu. Returns the panel. */
    ScanPanel openRequest(HttpRequest request) {
        ScanPanel panel = addTab(request, defaultTitle(request));
        if (request != null) {
            panel.loadRequest(request);
        }
        return panel;
    }

    private ScanPanel addTab(HttpRequest request, String title) {
        ScanPanel panel = new ScanPanel(api, runner, this);
        // Insert before the trailing "+" tab so it stays last.
        int insertAt = tabs.indexOfComponent(plusPlaceholder);
        if (insertAt < 0) {
            insertAt = tabs.getTabCount();
        }
        tabs.insertTab(title, null, panel.getComponent(), null, insertAt);
        int idx = tabs.indexOfComponent(panel.getComponent());
        RenamableTabHeader header = new RenamableTabHeader(
                tabs, panel.getComponent(), title, () -> closeTab(panel));
        tabs.setTabComponentAt(idx, header);
        tabs.setSelectedIndex(idx);
        return panel;
    }

    private void closeTab(ScanPanel panel) {
        int idx = tabs.indexOfComponent(panel.getComponent());
        if (idx >= 0) {
            tabs.removeTabAt(idx);
        }
        panel.dispose();
        VulnEntry entry = vulnByPanel.remove(panel);
        if (entry != null) {
            vulnModel.removeElement(entry);
        }
        // Keep at least one real tab besides the "+" placeholder.
        int realTabs = tabs.getTabCount() - (tabs.indexOfComponent(plusPlaceholder) >= 0 ? 1 : 0);
        if (realTabs <= 0) {
            addBlankTab();
        }
    }

    void selectPanel(ScanPanel panel) {
        int idx = tabs.indexOfComponent(panel.getComponent());
        if (idx >= 0) {
            tabs.setSelectedIndex(idx);
        }
    }

    /** Called by a ScanPanel when its scan confirms a vulnerability. */
    void markVulnerable(ScanPanel panel, HttpRequest request, ScanResultParser.Summary s) {
        String label = describe(request, s);
        VulnEntry existing = vulnByPanel.get(panel);
        if (existing != null) {
            existing.text = label;
            existing.summary = s;
            existing.header = headerLine(request, s);
            vulnList.repaint();
            if (vulnList.getSelectedValue() == existing) {
                detailArea.setText(renderDetail(existing));
                detailArea.setCaretPosition(0);
            }
        } else {
            VulnEntry entry = new VulnEntry(panel, label, s, headerLine(request, s));
            vulnByPanel.put(panel, entry);
            vulnModel.addElement(entry);
        }
        int idx = tabs.indexOfComponent(panel.getComponent());
        if (idx >= 0 && tabs.getTabComponentAt(idx) instanceof RenamableTabHeader header) {
            header.setVulnerable(true);
        }
    }

    /** Full details of one finding, shown in the left detail pane. */
    private String renderDetail(VulnEntry e) {
        ScanResultParser.Summary s = e.summary;
        StringBuilder sb = new StringBuilder();
        sb.append(e.header).append("\n\n");
        sb.append("Injection points:\n");
        for (ScanResultParser.Injection inj : s.injectionPoints) {
            sb.append("  ").append(inj.parameter).append(" — ").append(inj.type);
            if (!inj.title.isEmpty()) {
                sb.append(" (").append(inj.title).append(")");
            }
            sb.append("\n");
        }
        if (!s.tables.isEmpty()) {
            sb.append("\nTables enumerated:\n");
            for (String t : s.tables) {
                sb.append("  ").append(t).append("\n");
            }
        }
        if (!s.databases.isEmpty()) {
            sb.append("\nDatabases:\n");
            for (String d : s.databases) {
                sb.append("  ").append(d).append("\n");
            }
        }
        if (!s.dumpedTables.isEmpty()) {
            sb.append("\nDumped data:\n");
            for (ScanResultParser.DumpedTable dt : s.dumpedTables) {
                sb.append("\nTable: ").append(dt.name).append("\n");
                for (String l : dt.lines) {
                    sb.append(l).append("\n");
                }
            }
        }
        return sb.toString();
    }

    private String headerLine(HttpRequest request, ScanResultParser.Summary s) {
        String host = request != null && request.httpService() != null
                ? request.httpService().host() : "target";
        StringBuilder sb = new StringBuilder(host).append(pathOf(request));
        if (!s.dbms.isEmpty()) {
            sb.append("\nBack-end DBMS: ").append(s.dbms);
            if (!s.banner.isEmpty()) {
                sb.append(" (").append(s.banner).append(")");
            }
        }
        return sb.toString();
    }

    private String describe(HttpRequest request, ScanResultParser.Summary s) {
        String host = request != null && request.httpService() != null
                ? request.httpService().host() : "target";
        StringBuilder sb = new StringBuilder();
        sb.append(host).append(pathOf(request))
          .append("  —  ").append(s.injectionPoints.size()).append(" technique(s)");
        if (!s.dbms.isEmpty()) {
            sb.append(" • ").append(s.dbms);
        }
        if (!s.tables.isEmpty()) {
            sb.append(" • ").append(s.tables.size()).append(" table(s)");
        }
        return sb.toString();
    }

    private static String defaultTitle(HttpRequest request) {
        if (request == null) {
            return "Scan";
        }
        String host = request.httpService() != null ? request.httpService().host() : "";
        String title = host + pathOf(request);
        if (title.isBlank()) {
            title = "Scan";
        }
        return title.length() > 30 ? title.substring(0, 29) + "…" : title;
    }

    private static String pathOf(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String u = request.url();
            int i = u.indexOf("://");
            if (i >= 0) {
                u = u.substring(i + 3);
            }
            int slash = u.indexOf('/');
            String path = slash >= 0 ? u.substring(slash) : "/";
            int q = path.indexOf('?');
            return q >= 0 ? path.substring(0, q) : path;
        } catch (Exception e) {
            return "";
        }
    }

    /** A row in the left-hand vulnerable list, linked to its ScanPanel. */
    private static class VulnEntry {
        final ScanPanel panel;
        String text;
        ScanResultParser.Summary summary;
        String header;

        VulnEntry(ScanPanel panel, String text, ScanResultParser.Summary summary, String header) {
            this.panel = panel;
            this.text = text;
            this.summary = summary;
            this.header = header;
        }

        @Override
        public String toString() {
            return text;
        }
    }
}
