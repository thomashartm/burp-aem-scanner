package burp.actions.accesscontrol;

import burp.*;
import burp.actions.SecurityCheck;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Checks for sling pot servlet related issues.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class AnonymousWriteAccessCheckCallable implements SecurityCheck {

    private static final String ISSUE_NAME = "Anonymous write access is enabled";

    private static final String TESTNODE_CONTENT_USERGENERATED = "/content/usergenerated/mytestnode";

    private final IHttpRequestResponse baseMessage;

    private final BurpHelperDto helperDto;

    /**
     * Constructor
     * @param helperDto
     * @param baseMessage
     */
    public AnonymousWriteAccessCheckCallable(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        this.helperDto = helperDto;
        this.baseMessage = baseMessage;
    }

    public IExtensionHelpers getHelpers() {
        return this.helperDto.getHelpers();
    }

    @Override
    public Boolean call() throws Exception {
        scan(baseMessage).forEach(iScanIssue -> this.helperDto.getCallbacks().addScanIssue(iScanIssue));
        return true;
    }

    @Override
    public List<IScanIssue> scan(IHttpRequestResponse baseRequestResponse) {
        final List<IScanIssue> results = new ArrayList<>();

        final IHttpService httpService = baseRequestResponse.getHttpService();
        try {
            final URL targetUrl = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(),
                    TESTNODE_CONTENT_USERGENERATED);
            byte[] baseGetRequest = getHelpers().buildHttpRequest(targetUrl);
            byte[] postRequest = getHelpers().toggleRequestMethod(baseGetRequest);

            final IHttpRequestResponse requestResponse = this.helperDto.getCallbacks().makeHttpRequest(httpService, postRequest);
            final IResponseInfo responseInfo = getHelpers().analyzeResponse(requestResponse.getResponse());
            final short statusCode = responseInfo.getStatusCode();

            this.helperDto.getCallbacks().printOutput(String.format("Access control check: %s with statuscode %s", targetUrl.toString(), String.valueOf(statusCode)));

            if (statusCode == 200) {
                final ScanIssue scanIssue = report(requestResponse, targetUrl);
                results.add(scanIssue);
            }
        } catch (MalformedURLException e) {
            this.helperDto.getCallbacks().printError(e.toString());
        }

        return results;
    }

    private ScanIssue report(IHttpRequestResponse requestResponse , final URL url){
        final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, ISSUE_NAME,
                "Anonymous write access to the repository is enabled.");
        builder.withUrl(url);
        builder.withSeverityMedium();
        builder.withCertainConfidence();

        return builder.build();
    }
}
