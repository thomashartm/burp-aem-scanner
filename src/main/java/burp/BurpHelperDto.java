package burp;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;

/**
 * Transports all relevant objects to be consumed by menu items
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class BurpHelperDto {

    BurpExtender extender;
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;
    IContextMenuInvocation iContextMenuInvocation;

    public BurpHelperDto(BurpExtender extender, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            IContextMenuInvocation iContextMenuInvocation) {
        this.extender = extender;
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.iContextMenuInvocation = iContextMenuInvocation;
    }

    public BurpExtender getExtender() {
        return extender;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    public IContextMenuInvocation getiContextMenuInvocation() {
        return iContextMenuInvocation;
    }
}
