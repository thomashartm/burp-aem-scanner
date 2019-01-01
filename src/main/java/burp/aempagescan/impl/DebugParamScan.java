package burp.aempagescan.impl;

import burp.*;
import burp.aempagescan.ActiveAemPageScan;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.util.Collections;
import java.util.List;

/**
 * Appends the debug parameter and verifies if the WCM debug filter is enabled.
 * In this case the page contains debug information.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class DebugParamScan implements ActiveAemPageScan, WithIssueBuilder {

    private static final String ISSUE_NAME = "AEM Debug Filter enabled";

    private static final String CELL_REFERENCE = "<br>cell=";

    private static final String DEBUG_LAYOUT_PARAM = "?debug=layout";

    private final IBurpExtenderCallbacks callbacks;

    private final IExtensionHelpers helpers;

    public DebugParamScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse, final URL aemPageUrl) {

        final byte[] request = this.helpers.buildHttpRequest(aemPageUrl);
        final IParameter parameter = this.helpers.buildParameter("debug", "layout", IParameter.PARAM_URL);
        final byte[] debugRequest = this.helpers.addParameter(request, parameter);

        final IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), debugRequest);

        final byte[] response = requestResponse.getResponse();
        final IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

        if (cellInfoIsPresent(response, responseInfo)) {
            final String details = "Debug filter for AEM is active and should be disabled on publishing instances.";
            final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, ISSUE_NAME, details);

            // we use the original URL as we else spam the target tree with all mutations.
            builder.withUrl(aemPageUrl);
            builder.withSeverityLow();
            builder.withCertainConfidence();

            return toList(builder.build());
        }

        return Collections.emptyList();
    }

    private boolean cellInfoIsPresent(byte[] response, IResponseInfo responseInfo) {
        return responseInfo.getStatusCode() == 200 && StringUtils.containsAny(this.helpers.bytesToString(response), CELL_REFERENCE);
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helpers;
    }
}
