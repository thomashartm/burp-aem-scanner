package burp.dispatcher;

import burp.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

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
public class DispatcherSecurityCheck implements ConsolidatingScanner, WithIssueBuilder, IScannerInsertionPointProvider {

    private final IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    final CopyOnWriteArrayList<IScanIssue> reportableIssues = new CopyOnWriteArrayList<>();

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

        if (iScannerInsertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_URL_PATH_FILENAME && !this.reportableIssues
                .isEmpty()) {
            List<IScanIssue> reportedResults = new ArrayList<>();
            reportedResults.addAll(this.reportableIssues);
            // clean up old findings
            this.reportableIssues.clear();

            return reportedResults;
        }
        return Collections.emptyList();
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        /**
         * TODO Refactor Burp API limitation.
         * - Is there any other way to simply say "each active scanned HTTP requested once per scan"?
         *
         * Right now the API does not allow it:
         * https://support.portswigger.net/customer/en/portal/questions/16776337-confusion-on-insertionpoints-active-scan-module?new=16776337
         *
         * So we go for the same way as the UploadScanner extension and
         * misuse the getInsertionPoints method which is only called once per scan by coincidence
         * See https://github.com/PortSwigger/upload-scanner/blob/master/UploadScanner.py
         */

        this.callbacks.printOutput("Dispatcher getInsertionPoints called " + baseRequestResponse.toString());

        final IHttpService httpService = baseRequestResponse.getHttpService();
        try {
            for (final Vulnerability vulnerability : Vulnerability.values()) {
                final List<URL> urls = vulnerability.toUrl(httpService);
                for (final URL url : urls) {

                    final IHttpRequestResponse responseInfo = this.sendRequestsToDispatcher(url, httpService);
                    final Optional<ScanIssue> optionalIssue = this.evaluateResponse(url, vulnerability, responseInfo);

                    if (optionalIssue.isPresent()) {
                        this.reportableIssues.add(optionalIssue.get());
                    }
                }
            }
        } catch (MalformedURLException e) {
            this.callbacks.printError(e.toString());
        }

        return Collections.emptyList();
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

        final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, vulnerability.getName(),
                vulnerability.getDescription());

        // start here and may add additional information depending on the statuscode.
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

        return Optional.of(builder.build());
    }

    private boolean isInRange(short value, int lowerBound, int upperBound) {
        final Integer intval = Integer.valueOf(value);
        return lowerBound <= intval && intval <= upperBound;
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helpers;
    }
}
