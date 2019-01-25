package burp.checks.misconfiguration;

import burp.*;
import burp.checks.SecurityCheck;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.util.Collections;
import java.util.List;

/**
 * TODO - add javadoc
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class DebugFilterCallable implements SecurityCheck {

    private static final String ISSUE_NAME = "AEM Debug Filter enabled";

    private static final String CELL_REFERENCE = "<br>cell=";

    private static final String DEBUG_LAYOUT_PARAM = "?debug=layout";

    private final BurpHelperDto helperDto;

    private final IHttpRequestResponse baseMessage;

    public DebugFilterCallable(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        this.helperDto = helperDto;
        this.baseMessage = baseMessage;
    }

    @Override
    public Boolean call() {
        scan(baseMessage).forEach(iScanIssue -> this.helperDto.getCallbacks().addScanIssue(iScanIssue));
        return true;
    }

    @Override
    public List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse) {
        this.helperDto.getCallbacks().printOutput("DebugFilterCallable call submitted for execution");
        final IRequestInfo baseRequest = this.helperDto.getHelpers().analyzeRequest(baseRequestResponse.getRequest());
        final URL aemPageUrl = baseRequest.getUrl();

        final byte[] request = this.helperDto.getHelpers().buildHttpRequest(aemPageUrl);
        final IParameter parameter = this.helperDto.getHelpers().buildParameter("debug", "layout", IParameter.PARAM_URL);
        final byte[] debugRequest = this.helperDto.getHelpers().addParameter(request, parameter);

        final IHttpRequestResponse requestResponse = this.helperDto.getCallbacks()
                .makeHttpRequest(baseRequestResponse.getHttpService(), debugRequest);

        final byte[] response = requestResponse.getResponse();
        final IResponseInfo responseInfo = this.helperDto.getHelpers().analyzeResponse(response);

        if (cellInfoIsPresent(response, responseInfo)) {
            this.helperDto.getCallbacks().printOutput("DebugFilterCallable detected presence of token which indicates the debug filter is running");
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
        return responseInfo.getStatusCode() == 200 && StringUtils
                .containsAny(this.helperDto.getHelpers().bytesToString(response), CELL_REFERENCE);
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helperDto.getHelpers();
    }
}
