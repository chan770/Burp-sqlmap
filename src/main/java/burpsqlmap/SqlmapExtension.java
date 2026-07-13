package burpsqlmap;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Burp Suite Pro extension: "Standalone sqlmap".
 *
 * Runs sqlmap on a workstation that cannot install sqlmap (or even Python) by
 * bundling an embeddable Python runtime and the sqlmap source inside the JAR.
 * On first use the runtime is extracted to a temp directory and sqlmap is
 * driven as a subprocess. A selected Burp request is handed to sqlmap verbatim
 * (via a temporary request file) so headers, cookies and body are preserved.
 */
public class SqlmapExtension implements BurpExtension, ContextMenuItemsProvider {

    static final String NAME = "Standalone sqlmap";

    private MontoyaApi api;
    private SqlmapRunner runner;
    private SqlmapTab tab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(NAME);

        this.runner = new SqlmapRunner(api);
        this.tab = new SqlmapTab(api, runner);

        Registration uiReg = api.userInterface().registerSuiteTab(NAME, tab.getComponent());
        api.userInterface().registerContextMenuItemsProvider(this);

        api.extension().registerUnloadingHandler(() -> {
            runner.shutdown();
            uiReg.deregister();
            api.logging().logToOutput("[" + NAME + "] unloaded.");
        });

        api.logging().logToOutput("========================================");
        api.logging().logToOutput(" " + NAME + " loaded.");
        api.logging().logToOutput(" Bundled runtime — no local Python/sqlmap install required.");
        api.logging().logToOutput(" Right-click a request > 'Scan with sqlmap', or use the '" + NAME + "' tab.");
        api.logging().logToOutput("========================================");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        Optional<HttpRequest> selected = requestFrom(event);
        if (selected.isEmpty()) {
            return items;
        }
        HttpRequest request = selected.get();

        JMenuItem scan = new JMenuItem("Scan with sqlmap");
        scan.addActionListener(e -> SwingUtilities.invokeLater(() -> {
            ScanPanel panel = tab.openRequest(request);
            panel.startScan();
        }));

        JMenuItem sendToTab = new JMenuItem("Send request to sqlmap tab");
        sendToTab.addActionListener(e -> SwingUtilities.invokeLater(() -> tab.openRequest(request)));

        items.add(scan);
        items.add(sendToTab);
        return items;
    }

    private Optional<HttpRequest> requestFrom(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse ed = event.messageEditorRequestResponse().get();
            if (ed.requestResponse() != null && ed.requestResponse().request() != null) {
                return Optional.of(ed.requestResponse().request());
            }
        }
        if (!event.selectedRequestResponses().isEmpty()) {
            return Optional.ofNullable(event.selectedRequestResponses().get(0).request());
        }
        return Optional.empty();
    }
}
