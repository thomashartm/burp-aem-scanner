package burp;

import burp.dispatcher.AemFingerPrinterBasedPagesCheck;
import burp.dispatcher.DispatcherSecurityCheck;
import burp.sling.AnonymousWriteCheck;
import burp.sling.ErrorPagePlatformInfoLeakage;

/**
 * AEM Security Scanner - BurpExtender. This class registers the scanner checks-
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 11/2018
 */
public class BurpExtender implements IBurpExtender {

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

        final DispatcherSecurityCheck dispatcherSecurityCheck = new DispatcherSecurityCheck(this.callbacks);

        final AemFingerPrinterBasedPagesCheck contentGrabbingCheck = new AemFingerPrinterBasedPagesCheck(this.callbacks);
        callbacks.registerScannerCheck(contentGrabbingCheck);

        final ErrorPagePlatformInfoLeakage errorPagePlatformInfoLeakage = new ErrorPagePlatformInfoLeakage(this.callbacks);
        callbacks.registerScannerCheck(errorPagePlatformInfoLeakage);

        final AnonymousWriteCheck anonymousWriteCheck = new AnonymousWriteCheck(this.callbacks);
        callbacks.registerScannerCheck(anonymousWriteCheck);

        callbacks.registerScannerInsertionPointProvider(dispatcherSecurityCheck);
    }
}
