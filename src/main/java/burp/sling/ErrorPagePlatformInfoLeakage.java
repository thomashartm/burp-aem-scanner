package burp.sling;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Checks wether the platform discloses information about the target system by passively searching for address tags inside error pages.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class ErrorPagePlatformInfoLeakage implements ConsolidatingScanner, WithIssueBuilder {

    public static final String ERROR_PAGE_INFO_LEAKAGE = "Server platform information disclosed";

    private static final String ERROR_PAGE_INFO_DETAILS = "The error pages leaks information about the platform/runtime environment. See %s";

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    /**
     * @param callbacks
     */
    public ErrorPagePlatformInfoLeakage(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(final IHttpRequestResponse baseRequestResponse) {
        final List<IScanIssue> results = new ArrayList<>();

        final byte[] response = baseRequestResponse.getResponse();
        final IResponseInfo responseInfo = this.helpers.analyzeResponse(response);
        if (responseInfo.getStatusCode() >= 400) {

            final String responseMessage = this.helpers.bytesToString(response);
            final String[] addresses = StringUtils.substringsBetween(responseMessage, "<address>", "</address>");

            if (addresses.length > 0) {
                final String details = String.format(ERROR_PAGE_INFO_DETAILS, StringUtils.join(addresses, ","));
                final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(baseRequestResponse, ERROR_PAGE_INFO_LEAKAGE, details);
                // for now it is only information

                final IRequestInfo requestInfo = this.helpers
                        .analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
                callbacks.printOutput(String.format("Found platform info leakage %s", requestInfo.getUrl()));
                builder.withUrl(requestInfo.getUrl());
                builder.withSeverityLow();
                builder.withCertainConfidence();
                results.add(builder.build());
            }

        }
        return results;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {
        return Collections.emptyList();
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helpers;
    }
}
