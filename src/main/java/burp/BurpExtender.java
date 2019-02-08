package burp;

import burp.actions.SecurityCheckExecutorService;
import burp.ui.AEMSecurityAnalysisMenu;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * AEM Security Scanner - BurpExtender. This class registers the scanner checks-
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 11/2018
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {

    private static final String EXTENSION_NAME = "AEM Security Scanner";

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

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

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {

        final BurpHelperDto helperDto = new BurpHelperDto(this, this.callbacks, this.helpers, iContextMenuInvocation);

        final List<JMenuItem> menuItems = new ArrayList<>();
        JMenu dispatcherAnalysisMenu = new AEMSecurityAnalysisMenu(this.executorService, helperDto);
        menuItems.add(dispatcherAnalysisMenu);
        return menuItems;
    }
}
