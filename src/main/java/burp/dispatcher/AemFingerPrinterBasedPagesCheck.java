package burp.dispatcher;

import burp.*;
import burp.aempagescan.ActiveAemPageScan;
import burp.aempagescan.AemPageScanFactory;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Passive check which verifies if a page is an AEM delivered page.
 */
public class AemFingerPrinterBasedPagesCheck implements ConsolidatingScanner {

    private static final String AEM_FINGERPRINTER_MATCH = "Adobe AEM fingerprint detected";

    private static final String AEM_FINGERPRINTER_DETAILS = "The following tokens were detected [%s] inside the body of the following page %s. The target system has been identified as Adobe Experience Manager.";

    private static final String[] AEM_FINGERPRINTING_TOKENS = new String[] {
            "jcr_content/", "/etc.clientlibs", "/etc/designs",
    };

    private List<String> fingerPrintingKeywords;

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    public AemFingerPrinterBasedPagesCheck(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.fingerPrintingKeywords = Arrays.asList(AEM_FINGERPRINTING_TOKENS);
    }

    @Override
    public List<IScanIssue> doPassiveScan(final IHttpRequestResponse baseRequestResponse) {
        final List<IScanIssue> results = new ArrayList<>();

        final IResponseKeywords analyzedKeywords = this.helpers
                .analyzeResponseKeywords(fingerPrintingKeywords, baseRequestResponse.getResponse());

        final List<String> detectedKeywords = fingerPrintingKeywords.stream()
                .filter(keyword -> analyzedKeywords.getKeywordCount(keyword, 0) > 0).collect(Collectors.toList());

        // we have at least a match.
        if (detectedKeywords.size() > 0) {

            final IRequestInfo request = this.helpers
                    .analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
            final URL url = request.getUrl();

            final ScanIssue.ScanIssueBuilder builder = ScanIssue.ScanIssueBuilder.aScanIssue();
            builder.withUrl(url);

            builder.withHttpMessages(new IHttpRequestResponse[] { baseRequestResponse });
            builder.withHttpService(baseRequestResponse.getHttpService());

            builder.withName(AEM_FINGERPRINTER_MATCH);
            final String details = String.format(AEM_FINGERPRINTER_DETAILS, StringUtils.join(detectedKeywords, ","), url.toString());
            builder.withDetail(details);

            // for now it is only information
            builder.withSeverityInformation();
            builder.withCertainConfidence();

            results.add(builder.build());
        }

        return results;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {
        final List<IScanIssue> aemPageRelatedIssues = new ArrayList<>();

        final IScanIssue[] scanIssues = retrieveScanIssuesForTarget(baseRequestResponse);

        Arrays.asList(scanIssues)
                .stream()
                .filter(issue -> StringUtils.equals(AEM_FINGERPRINTER_MATCH, issue.getIssueName()))
                .map(issue -> issue.getUrl())
                .map(url -> applyAemSpecificScans(baseRequestResponse, url))
                .filter(list -> !list.isEmpty()).forEach(list -> aemPageRelatedIssues.addAll(list));

        return aemPageRelatedIssues;
    }

    private IScanIssue[] retrieveScanIssuesForTarget(IHttpRequestResponse baseRequestResponse) {
        final IHttpService httpService = baseRequestResponse.getHttpService();
        final String urlPrefix = String.format("%s://%s", httpService.getProtocol(), httpService.getHost());
        return this.callbacks.getScanIssues(urlPrefix);
    }

    private List<IScanIssue> applyAemSpecificScans(IHttpRequestResponse baseRequestResponse, final URL aemBasePageUrl) {
        final List<ActiveAemPageScan> scanList = AemPageScanFactory.createAEMPageScanners(this.callbacks);

        final List<IScanIssue> results = new ArrayList<>();
        scanList.stream().forEach(activeScan -> {
            List<IScanIssue> issues = activeScan.scan(baseRequestResponse, aemBasePageUrl);
            results.addAll(issues);
        });

        return results;
    }
}
