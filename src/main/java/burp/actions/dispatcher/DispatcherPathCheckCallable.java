package burp.actions.dispatcher;

import burp.*;
import burp.actions.SecurityCheck;
import burp.actions.WithHttpRequests;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Fires a set of HTTP calls to known dispatcher endpoints to verify if the dispatcher configuration protects them.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 * @deprecated Will be removed in the near future
 */
public class DispatcherPathCheckCallable implements SecurityCheck, WithHttpRequests {

    private final IHttpRequestResponse baseMessage;

    private final BurpHelperDto helperDto;

    /**
     * @param helperDto
     * @param baseMessage
     */
    public DispatcherPathCheckCallable(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        this.helperDto = helperDto;
        this.baseMessage = baseMessage;
    }

    @Override
    public Boolean call() throws Exception {
        scan(baseMessage).forEach(iScanIssue -> this.helperDto.getCallbacks().addScanIssue(iScanIssue));
        return true;
    }

    @Override
    public List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse) {
        final IBurpExtenderCallbacks callbacks = this.helperDto.getCallbacks();
        callbacks.printOutput("Dispatcher security check called. " + baseRequestResponse.toString());

        final List<IScanIssue> reportableIssues = new ArrayList<>();
        final IHttpService httpService = baseRequestResponse.getHttpService();
        try {
            for (final DispatcherConfigVulnerability vulnerability : DispatcherConfigVulnerability.values()) {
                callbacks.printOutput("Probing for " + vulnerability.getName());
                final List<URL> urls = vulnerability.toUrl(httpService);
                for (final URL url : urls) {
                    callbacks.printOutput(String.format("Probing %s with URL %s", vulnerability.getName(), url.toString()));

                    final IHttpRequestResponse responseInfo = this.sendRequest(url, httpService);
                    final Optional<ScanIssue> optionalIssue = this.analyzeResponseForStatusCodes(vulnerability, responseInfo);
                    if (optionalIssue.isPresent()) {
                        reportableIssues.add(optionalIssue.get());
                    }
                }
            }
        } catch (MalformedURLException e) {
            callbacks.printError("Unable to create target URL for " + e);
        }

        return reportableIssues;
    }

    @Override public String getName() {
        return null;
    }

    @Override public String getDescription() {
        return null;
    }

    @Override public Severity getSeverity() {
        return null;
    }

    @Override public Confidence getConfidence() {
        return null;
    }

    Optional<ScanIssue> analyzeResponseForStatusCodes(final DispatcherConfigVulnerability vulnerability,
            final IHttpRequestResponse requestResponse) {
        final IResponseInfo responseInfo = this.helperDto.getHelpers().analyzeResponse(requestResponse.getResponse());
        final short statusCode = responseInfo.getStatusCode();

        // we only follow on 2xx status codes for now as many dispatcher configs just redirect to the start page.
        // for the future it might also make sense to evaluate 302 and 301 and check where they are redirecting.
        if (!isInRange(statusCode, 200, 299)) {
            return Optional.empty();
        }

        final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, vulnerability.getName(),
                vulnerability.getDescription());

        // start here and may add additional information depending on the statuscode.
        builder.withSeverity(vulnerability.getSeverity());

        // success related status codes ... we need to look closely
        if (statusCode == 200) {
            builder.withCertainConfidence();
        } else {
            builder.withTenativeConfidence();
        }

        return Optional.of(builder.build());
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helperDto.getHelpers();
    }

    @Override
    public BurpHelperDto getHelperDto() {
        return this.helperDto;
    }
}
