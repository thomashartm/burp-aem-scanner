package burp.executeonce;

import burp.*;
import burp.dispatcher.Vulnerability;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * TODO - add javadoc
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class DispatcherPathModule implements ScannerModule {

    private final IBurpExtenderCallbacks callbacks;

    private final IExtensionHelpers helpers;

    public DispatcherPathModule(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> scan(IHttpRequestResponse baseRequestResponse) {
        this.callbacks.printOutput("Dispatcher security check called. " + baseRequestResponse.toString());

        final List<IScanIssue> reportableIssues = new ArrayList<>();
        final IHttpService httpService = baseRequestResponse.getHttpService();
        try {
            for (final Vulnerability vulnerability : Vulnerability.values()) {
                final List<URL> urls = vulnerability.toUrl(httpService);
                for (final URL url : urls) {
                    final IHttpRequestResponse responseInfo = this.sendRequestsToDispatcher(url, httpService);
                    final Optional<ScanIssue> optionalIssue = this.analyzeResponseForStatusCodes(vulnerability, responseInfo);
                    if (optionalIssue.isPresent()) {
                        reportableIssues.add(optionalIssue.get());
                    }
                }
            }
        } catch (MalformedURLException e) {
            this.callbacks.printError(e.toString());
        }

        return reportableIssues;
    }

    private IHttpRequestResponse sendRequestsToDispatcher(final URL url, final IHttpService httpService) {
        final byte[] request = this.helpers.buildHttpRequest(url);
        return this.callbacks.makeHttpRequest(httpService, request);
    }

    Optional<ScanIssue> analyzeResponseForStatusCodes(final Vulnerability vulnerability, final IHttpRequestResponse requestResponse) {
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
