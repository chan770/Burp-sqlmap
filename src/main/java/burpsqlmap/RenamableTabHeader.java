package burpsqlmap;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * A JTabbedPane tab header with a double-click-to-rename title (Repeater-style)
 * and a small close button. Single click selects the tab; double click edits
 * the name inline.
 */
class RenamableTabHeader extends JPanel {

    private final JTabbedPane pane;
    private final Component content;
    private final JLabel label;
    private final JTextField editor = new JTextField();

    RenamableTabHeader(JTabbedPane pane, Component content, String title, Runnable onClose) {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        this.pane = pane;
        this.content = content;
        setOpaque(false);

        label = new JLabel(title);
        label.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 4));

        MouseAdapter mouse = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    startEditing();
                } else {
                    int i = pane.indexOfComponent(content);
                    if (i >= 0) {
                        pane.setSelectedIndex(i);
                    }
                }
            }
        };
        label.addMouseListener(mouse);

        editor.addActionListener(e -> commitEditing());
        editor.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                commitEditing();
            }
        });

        JButton close = new JButton("×");
        close.setMargin(new Insets(0, 4, 0, 4));
        close.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 2));
        close.setContentAreaFilled(false);
        close.setFocusable(false);
        close.setToolTipText("Close tab");
        close.addActionListener(e -> onClose.run());

        add(label);
        add(close);
    }

    String getTitle() {
        return label.getText();
    }

    /** Mark the tab title (e.g. to flag a vulnerable result). */
    void setVulnerable(boolean vulnerable) {
        label.setForeground(vulnerable ? new Color(0xE0, 0x5a, 0x5a) : null);
        String t = label.getText();
        if (vulnerable && !t.startsWith("⚠ ")) {
            label.setText("⚠ " + t);
        }
    }

    private void startEditing() {
        editor.setText(label.getText().replaceFirst("^⚠ ", ""));
        remove(label);
        add(editor, 0);
        revalidate();
        editor.selectAll();
        editor.requestFocusInWindow();
    }

    private void commitEditing() {
        if (editor.getParent() != this) {
            return;
        }
        String text = editor.getText().trim();
        if (!text.isEmpty()) {
            label.setText(text);
        }
        remove(editor);
        add(label, 0);
        revalidate();
        repaint();
    }
}
