package burp.dispatcher;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Checks wether the website is vulnerable to content grabbing via sling default selectors.
 * These selector will provide alternate renditions of the currently requested page and may
 * lead to the disclosure of confidential metainformation e.g. user name via the cq:lastModified property.
 * The following selector.extension combinations can be considered critical.
 * <p>
 * .infinity.json, .tidy.json, .sysview.xml, .docview.json, .docview.xml, .-1.json, .1.json, .2.json, .query.json, .xml
 * The list is based on https://helpx.adobe.com/experience-manager/dispatcher/using/security-checklist.html#RestrictAccess
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class ContentGrabbingCheck implements IScannerCheck {

    private static final String AEM_FINGERPRINTER_MATCH = "AEM Fingerprinting successfull";
    private static final String KEYWORD_MATCH_DETECTED = "The following tokens were detected [%s] inside the body of the following page %s. The target system has been identified as Adobe Experience Manager.";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static final String[] AEM_FINGERPRINTING_TOKENS = new String[] {
            "jcr_content/", "/etc.clientlibs", "/etc/designs",
    };
    private List<String> fingerPrintingKeywords;

    public ContentGrabbingCheck(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.fingerPrintingKeywords = Arrays.asList(AEM_FINGERPRINTING_TOKENS);
    }

    @Override
    public List<IScanIssue> doPassiveScan(final IHttpRequestResponse iHttpRequestResponse) {
        final List<IScanIssue> results = new ArrayList<>();

        final IResponseKeywords analyzedKeywords = this.helpers
                .analyzeResponseKeywords(fingerPrintingKeywords, iHttpRequestResponse.getResponse());

        final List<String> detectedKeywords = fingerPrintingKeywords.stream()
                .filter(keyword -> analyzedKeywords.getKeywordCount(keyword, 0) > 0).collect(Collectors.toList());

        // we have at least a match.
        if (detectedKeywords.size() > 0) {

            final IRequestInfo request = this.helpers.analyzeRequest(iHttpRequestResponse.getRequest());
            final URL url = request.getUrl();

            final ScanIssue.ScanIssueBuilder builder = ScanIssue.ScanIssueBuilder.aScanIssue();
            builder.withUrl(url);

            builder.withHttpMessages(new IHttpRequestResponse[] { iHttpRequestResponse });
            builder.withHttpService(iHttpRequestResponse.getHttpService());

            builder.withName(AEM_FINGERPRINTER_MATCH);
            final String details = String.format(KEYWORD_MATCH_DETECTED, StringUtils.join(detectedKeywords, ","), url.toString());
            builder.withDetail(details);

            // for now it is only information
            builder.withSeverityInformation();
            builder.withCertainConfidence();

            results.add(builder.build());
        }

        return results;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {



        return Collections.emptyList();
    }

    @Override
    public int consolidateDuplicateIssues(final IScanIssue existingIssue, final IScanIssue newIssue) {
        final boolean areSameIssues = existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail()
                .equals(newIssue.getIssueDetail());
        return areSameIssues ? -1 : 0;
    }
}
