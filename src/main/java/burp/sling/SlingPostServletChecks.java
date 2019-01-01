package burp.sling;

import burp.*;

import java.util.Collections;
import java.util.List;

/**
 * TODO - add javadoc
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class SlingPostServletChecks implements ConsolidatingScanner {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    /**
     * @param callbacks
     */
    public SlingPostServletChecks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {
        return Collections.emptyList();
    }
}
