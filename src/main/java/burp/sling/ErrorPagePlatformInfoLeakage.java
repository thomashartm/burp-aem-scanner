package burp.sling;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.List;

/**
 * Checks wether the platform discloses information about the target system by passively searching for address tags inside error pages.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class ErrorPagePlatformInfoLeakage implements IScannerCheck {

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    public ErrorPagePlatformInfoLeakage(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(final IHttpRequestResponse baseRequestResponse) {
        final byte[] response = baseRequestResponse.getResponse();
        final IResponseInfo responseInfo = this.helpers.analyzeResponse(response);
        if (responseInfo.getStatusCode() >= 400) {
            final String responseMessage = this.helpers.bytesToString(response);
            final String[] addresses = StringUtils.substringsBetween(responseMessage, "<address>", "</address>");
            if (addresses.length > 0) {

            }

        }
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {
        return Collections.emptyList();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }
}
