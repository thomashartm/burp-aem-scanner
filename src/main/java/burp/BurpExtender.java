package burp;

import biz.netcentric.aem.securitycheck.SecurityCheckService;
import biz.netcentric.aem.securitycheck.SecurityCheckServiceFactory;
import burp.data.BurpHelperDto;
import burp.ui.SecurityCheckMenu;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * This plugin context create a menu entry which allows to trigger a security scan of AEM using the integrated checks
 */
public class BurpExtender extends JMenu implements IBurpExtender, IContextMenuFactory {

    private static final String EXTENSION_NAME = "AEM Security Scanner";

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private SecurityCheckService securityCheckService;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName(EXTENSION_NAME);
        this.callbacks.registerContextMenuFactory(this);// for menus
        this.securityCheckService = SecurityCheckServiceFactory.createSecurityCheckService();
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        final BurpHelperDto helperDto = new BurpHelperDto(this, this.callbacks, this.helpers, iContextMenuInvocation);

        final List<JMenuItem> menuItems = new ArrayList<>();
        JMenu dispatcherAnalysisMenu = new SecurityCheckMenu(this.securityCheckService, helperDto);
        menuItems.add(dispatcherAnalysisMenu);
        return menuItems;
    }
}
