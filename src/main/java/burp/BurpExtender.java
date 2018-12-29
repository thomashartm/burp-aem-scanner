package burp;

import burp.dispatcher.DispatcherSecurityCheck;

/**
 * TODO - add javadoc
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

        DispatcherSecurityCheck dispatcherSecurityCheck = new DispatcherSecurityCheck(this.callbacks);
        // register all custom scanner checks
        callbacks.registerScannerCheck(dispatcherSecurityCheck);
    }
}
