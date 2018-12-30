package burp;

import burp.dispatcher.ContentGrabbingCheck;
import burp.dispatcher.DispatcherSecurityCheck;

/**
 * AEM Security Scanner - BurpExtender. This class registers the scanner checks-
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 11/2018
 */
public class BurpExtender implements IBurpExtender {

    private static final String EXTENSION_NAME = "AEM Security Checklist Validator";

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
        callbacks.registerScannerCheck(dispatcherSecurityCheck);

        final ContentGrabbingCheck contentGrabbingCheck = new ContentGrabbingCheck(this.callbacks);
        callbacks.registerScannerCheck(contentGrabbingCheck);
    }
}
