package burp;

import burp.aempagescan.AemFingerPrinterBasedPagesScanner;
import burp.executeonce.AnonymousWriteModule;
import burp.aempagescan.ErrorPagePlatformInfoLeakageScanner;
import burp.executeonce.ExecuteModulesOnceScanner;

/**
 * AEM Security Scanner - BurpExtender. This class registers the scanner checks-
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 11/2018
 */
public class BurpExtender implements IBurpExtender{

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

        // register all custom scanner checks

        final ErrorPagePlatformInfoLeakageScanner errorPagePlatformInfoLeakage = new ErrorPagePlatformInfoLeakageScanner(this.callbacks);
        callbacks.registerScannerCheck(errorPagePlatformInfoLeakage);

        // register as an insertion point provider
        final ExecuteModulesOnceScanner executeModulesOnceScanner = new ExecuteModulesOnceScanner(this.callbacks);
        callbacks.registerScannerInsertionPointProvider(executeModulesOnceScanner);
    }

}
