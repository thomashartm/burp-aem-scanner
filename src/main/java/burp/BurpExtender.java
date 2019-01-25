package burp;

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

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        this.callbacks.registerContextMenuFactory(this);// for menus



        // register all custom scanner checks

        //final ErrorPagePlatformInfoLeakageScanner errorPagePlatformInfoLeakage = new ErrorPagePlatformInfoLeakageScanner(this.callbacks);
        //callbacks.registerScannerCheck(errorPagePlatformInfoLeakage);

        // register as an insertion point provider
        //final ExecuteModulesOnceScanner executeModulesOnceScanner = new ExecuteModulesOnceScanner(this.callbacks);
        //callbacks.registerScannerInsertionPointProvider(executeModulesOnceScanner);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {

        final BurpHelperDto helperDto = new BurpHelperDto(this, this.callbacks, this.helpers, iContextMenuInvocation);

        final List<JMenuItem> menuItems = new ArrayList<>();
        JMenu dispatcherAnalysisMenu = new AEMSecurityAnalysisMenu(helperDto);
        menuItems.add(dispatcherAnalysisMenu);
        return menuItems;
    }
}
