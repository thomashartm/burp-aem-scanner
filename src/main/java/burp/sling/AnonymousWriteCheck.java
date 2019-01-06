package burp.sling;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Checks for sling pot servlet related issues.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class AnonymousWriteCheck implements ConsolidatingScanner, WithIssueBuilder {

    private static final String ISSUE_NAME = "Anonymous write access is enabled";

    private final IBurpExtenderCallbacks callbacks;

    private final IExtensionHelpers helpers;

    /**
     * @param callbacks
     */
    public AnonymousWriteCheck(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(final IHttpRequestResponse iHttpRequestResponse,
            final IScannerInsertionPoint iScannerInsertionPoint) {
        final List<IScanIssue> results = new ArrayList<>();
        if (iScannerInsertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_URL_PATH_FILENAME) {
            final IHttpService httpService = iHttpRequestResponse.getHttpService();
            try {
                final URL targetUrl = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(),
                        "/content/usergenerated/mytestnode");
                byte[] baseGetRequest = this.helpers.buildHttpRequest(targetUrl);
                byte[] postRequest = this.helpers.toggleRequestMethod(baseGetRequest);

                final IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(httpService, postRequest);
                final IResponseInfo responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
                final short statusCode = responseInfo.getStatusCode();
                callbacks
                        .printOutput(String.format("Active Scan: %s with statuscode %s", targetUrl.toString(), String.valueOf(statusCode)));

                if (statusCode == 200) {
                    final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, ISSUE_NAME,
                            "Anonymous write access to the repository is enabled.");
                    builder.withUrl(targetUrl);
                    builder.withSeverityMedium();
                    builder.withCertainConfidence();
                    results.add(builder.build());
                }
            } catch (MalformedURLException e) {
                callbacks.printError(e.toString());
            }
        }
        return results;
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helpers;
    }
}
