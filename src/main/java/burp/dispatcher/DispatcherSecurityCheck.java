package burp.dispatcher;

import burp.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * The AEM Dispatcher should restrict external access to critical and administrative resources as much as possible.
 * This active scanner checks for dispatcher security issues by actively requesting access to administrative URLs and checking it it is denied.
 * See @{@link Vulnerability} for the list of requested endpoints.
 * <p>
 * Checks are based on https://helpx.adobe.com/experience-manager/dispatcher/using/dispatcher-configuration.html#TestingDispatcherSecurity.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class DispatcherSecurityCheck implements ConsolidatingScanner {

    private final IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public DispatcherSecurityCheck(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(final IHttpRequestResponse baseRequestResponse,
            final IScannerInsertionPoint iScannerInsertionPoint) {
        final List<IScanIssue> reportableIssues = new ArrayList<>();

        final IHttpService httpService = baseRequestResponse.getHttpService();
        try {
            for (final Vulnerability vulnerability : Vulnerability.values()) {
                final List<URL> urls = vulnerability.toUrl(httpService);
                for (final URL url : urls) {

                    final IHttpRequestResponse responseInfo = this.sendRequestsToDispatcher(url, httpService);
                    final Optional<ScanIssue> optionalIssue = this.evaluateResponse(url, vulnerability, responseInfo);

                    if (optionalIssue.isPresent()) {
                        reportableIssues.add(optionalIssue.get());
                    }

                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return reportableIssues;
    }

    private IHttpRequestResponse sendRequestsToDispatcher(final URL url, final IHttpService httpService) {
        final byte[] request = this.helpers.buildHttpRequest(url);
        return this.callbacks.makeHttpRequest(httpService, request);
    }

    Optional<ScanIssue> evaluateResponse(final URL url, final Vulnerability vulnerability, final IHttpRequestResponse requestResponse) {
        final IResponseInfo responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
        final short statusCode = responseInfo.getStatusCode();

        // NOT_FOUND is ideal, which means dispatcher does not give access or leak info
        if (statusCode == 404) {
            return Optional.empty();
        }

        // ok it is not a 404 so we gonna report it
        final ScanIssue.ScanIssueBuilder builder = ScanIssue.ScanIssueBuilder.aScanIssue();
        builder.withUrl(url);
        builder.withName(vulnerability.getName());
        builder.withHttpMessages(new IHttpRequestResponse[] { requestResponse });
        builder.withHttpService(requestResponse.getHttpService());

        // start here and may add additional information depending on the statuscode.
        final StringBuilder detailBuilder = new StringBuilder(vulnerability.getDescription());
        builder.withSeverity(vulnerability.getSeverity());
        if (isInRange(statusCode, 200, 399)) {
            // success related status codes ... we need to look closely
            if (statusCode == 200 || statusCode == 302) {
                builder.withCertainConfidence();
            } else {
                builder.withTenativeConfidence();
            }
        } else {
            builder.withTenativeConfidence();
        }
        builder.withDetail(detailBuilder.toString());

        return Optional.of(builder.build());
    }

    private boolean isInRange(short value, int lowerBound, int upperBound) {
        final Integer intval = Integer.valueOf(value);
        return lowerBound <= intval && intval <= upperBound;
    }
}
