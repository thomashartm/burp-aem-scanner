package burp.executeonce;

import burp.*;

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
public class AnonymousWriteModule implements ScannerModule {

    private static final String ISSUE_NAME = "Anonymous write access is enabled";
    public static final String TESTNODE_CONTENT_USERGENERATED = "/content/usergenerated/mytestnode";

    private final IBurpExtenderCallbacks callbacks;

    private final IExtensionHelpers helpers;

    /**
     * @param callbacks
     */
    public AnonymousWriteModule(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public IExtensionHelpers getHelpers() {
        return this.helpers;
    }

    @Override
    public List<IScanIssue> scan(IHttpRequestResponse baseRequestResponse) {
        final List<IScanIssue> results = new ArrayList<>();

        final IHttpService httpService = baseRequestResponse.getHttpService();
        try {
            final URL targetUrl = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(),
                    TESTNODE_CONTENT_USERGENERATED);
            byte[] baseGetRequest = this.helpers.buildHttpRequest(targetUrl);
            byte[] postRequest = this.helpers.toggleRequestMethod(baseGetRequest);

            final IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(httpService, postRequest);
            final IResponseInfo responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
            final short statusCode = responseInfo.getStatusCode();

            this.callbacks.printOutput(String.format("Active Scan: %s with statuscode %s", targetUrl.toString(), String.valueOf(statusCode)));

            if (statusCode == 200) {
                final ScanIssue scanIssue = report(requestResponse, targetUrl);
                results.add(scanIssue);
            }
        } catch (MalformedURLException e) {
            this.callbacks.printError(e.toString());
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
