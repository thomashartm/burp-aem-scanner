package burp.data;

import biz.netcentric.aem.securitycheck.util.Logger;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import lombok.Getter;

/**
 * Transports all relevant objects to be consumed actions triggered from within the scanner
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
@Getter
public class BurpHelperDto {

    private CallbackLogger logger;

    private IContextMenuInvocation iContextMenuInvocation;

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private BurpExtender extender;

    public BurpHelperDto(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.logger = new CallbackLogger(this.callbacks);
        this.extender = null;
        this.iContextMenuInvocation = null;
    }

    public BurpHelperDto(final BurpExtender extender, final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final IContextMenuInvocation iContextMenuInvocation) {
        this.extender = extender;
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.iContextMenuInvocation = iContextMenuInvocation;
        this.logger = new CallbackLogger(this.callbacks);
    }
}
