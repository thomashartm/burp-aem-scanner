package burp;

import biz.netcentric.aem.securitycheck.checks.service.SecurityCheckExecutorService;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class BurpExtender extends JMenu implements IBurpExtender, IContextMenuFactory {

    private static final String EXTENSION_NAME = "AEM Security Scanner";

    public static final String PARAM_BODY = "body";

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private IHttpRequestResponse baseMessage;

    private URL url;

    private String method;

    private List<String> headers = new ArrayList<>();

    private Map<String, String> parameters = new LinkedHashMap<>();

    private String body;

    private byte[] currentRequest;

    private SecurityCheckExecutorService executorService;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        this.executorService = new SecurityCheckExecutorService(5);

        this.callbacks.registerContextMenuFactory(this);// for menus
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {

        final List<JMenuItem> menuItems = new ArrayList<>();

        //register("AuditLogServlet enabled", new GenericCheckActionListener(this.executorService, helperDto, AuditServletDetector.class));

        return menuItems;
    }


    private void register(final String name, final ActionListener actionListener) {
        final JMenuItem menuItem = new JMenuItem(name);
        menuItem.addActionListener(actionListener);
        this.add(menuItem);
    }

    private void addMenuSeparator() {
        this.addSeparator();
    }
}
