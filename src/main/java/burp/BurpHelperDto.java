package burp;

/**
 * Transports all relevant objects to be consumed actions triggered from within the scanner
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class BurpHelperDto {

    private BurpExtender extender;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IContextMenuInvocation iContextMenuInvocation;

    public BurpHelperDto(final IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.extender = null;
        this.iContextMenuInvocation = null;
    }

    public BurpHelperDto(final BurpExtender extender, final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers, final IContextMenuInvocation iContextMenuInvocation) {
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
