package burp.dispatcher;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
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
public class ContentGrabbingCheck implements ConsolidatingScanner {

    private static final String AEM_FINGERPRINTER_MATCH = "Adobe AEM fingerprint detected";

    private static final String AEM_CONTENT_GRABBING_NAME = "Adobe AEM information leakage";

    private static final String AEM_FINGERPRINTER_DETAILS = "The following tokens were detected [%s] inside the body of the following page %s. The target system has been identified as Adobe Experience Manager.";

    private static final String[] AEM_FINGERPRINTING_TOKENS = new String[] {
            "jcr_content/", "/etc.clientlibs", "/etc/designs",
    };

    private List<String> fingerPrintingKeywords;

    private static final String[] CONTENT_GRAPPING_SUFFIXES = new String[] {
            ".tidy.-100.json", ".-1.json", ".infinity.json", ".1.json", ".10.json", ".tidy.blubber.json", ".blubber.json",
            ".languages.json", ".pages.json", ".blueprint.json", ".docview.xml", ".docview.json", ".sysview.xml", ".jcr:content.feed",
            "._jcr_content.feed"
    };

    private static final String[] CONTENT_GRAPPING_PATH_ELEMENTS = new String[] {
            "/jcr:content.feed", "/_jcr_content.feed", "/jcr:content.json", "/_jcr_content.json"
    };

    private static final String[] QUERY_EXTENSIONS = new String[] {
            ".query.json?statement=//*", ".qu%65ry.js%6Fn?statement=//*",
            ".query.json?statement=//*[@transportPassword]/(@transportPassword%20|%20@transportUri%20|%20@transportUser)"
    };

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    public ContentGrabbingCheck(final IBurpExtenderCallbacks callbacks) {
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
        final List<IScanIssue> contentGrabbingIssues = new ArrayList<>();

        final IHttpService httpService = baseRequestResponse.getHttpService();
        final String urlPrefix = String.format("%s://%s", httpService.getProtocol(), httpService.getHost());
        final IScanIssue[] scanIssues = this.callbacks.getScanIssues(urlPrefix);
        Arrays.asList(scanIssues)
                .stream()
                .filter(issue -> StringUtils.equals(AEM_FINGERPRINTER_MATCH, issue.getIssueName()))
                .map(issue -> issue.getUrl())
                .map(url -> probeContentGrabbing(httpService, url))
                .filter(list -> !list.isEmpty()).forEach(list -> contentGrabbingIssues.addAll(list));

        return contentGrabbingIssues;
    }

    private List<IScanIssue> probeContentGrabbing(final IHttpService httpService, final URL url) {
        final List<IScanIssue> results = new ArrayList<>();
        try {
            final List<URL> mutations = new ArrayList<>();
            mutations.addAll(createSuffixMutations(url));
            mutations.addAll(createPathMutations(url));
            mutations.addAll(createQueryMutations(url));

            for (final URL mutation : mutations) {
                final byte[] request = this.helpers.buildHttpRequest(mutation);
                IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(httpService, request);

                final IResponseInfo responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
                final short statusCode = responseInfo.getStatusCode();

                if (statusCode != 404) {
                    // AEM is responding to the message, now we need to evaluate the response
                    final IRequestInfo requestInfo = this.helpers
                            .analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
                    final URL requestUrl = requestInfo.getUrl();

                    final ScanIssue.ScanIssueBuilder builder = ScanIssue.ScanIssueBuilder.aScanIssue();
                    builder.withUrl(requestUrl);
                    builder.withHttpMessages(new IHttpRequestResponse[] { requestResponse });
                    builder.withHttpService(requestResponse.getHttpService());
                    builder.withName(AEM_CONTENT_GRABBING_NAME);

                    final String details = String
                            .format("The page %s is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block the mutation %s. Currently it responds with statuscode %s",
                                    url.toString(), mutation.toString(), String.valueOf(statusCode));
                    builder.withDetail(details);

                    if (isInRange(statusCode, 200, 399)) {
                        // success related status codes ... we need to look closely
                        if (statusCode == 200 || statusCode == 302) {
                            builder.withSeverityMedium();
                        } else {
                            builder.withSeverityInformation();
                        }
                        builder.withCertainConfidence();
                    } else {
                        builder.withSeverityInformation();
                        builder.withCertainConfidence();
                    }

                    results.add(builder.build());
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return results;
    }

    private boolean isInRange(short value, int lowerBound, int upperBound) {
        final Integer intval = Integer.valueOf(value);
        return lowerBound <= intval && intval <= upperBound;
    }

    private List<URL> createSuffixMutations(final URL url) throws MalformedURLException {
        final List<URL> mutations = new ArrayList<>();
        final String file = url.getFile();

        if (file.contains(".html")) {
            for (final String suffix : CONTENT_GRAPPING_SUFFIXES) {
                final String mutatedFile = file.replace(".html", suffix);
                final URL newMutatedUrl = new URL(url.getProtocol(), url.getHost(), Integer.valueOf(url.getPort()), mutatedFile);
                mutations.add(newMutatedUrl);
            }
        }

        return mutations;
    }

    private List<URL> createPathMutations(final URL url) throws MalformedURLException {
        final List<URL> mutations = new ArrayList<>();
        final String path = url.getPath();
        final int indexOfLastSlash = path.lastIndexOf("/");
        if (indexOfLastSlash > 0) {
            final String parentPath = StringUtils.substringBeforeLast(path, "/");
            for (final String suffix : CONTENT_GRAPPING_PATH_ELEMENTS) {
                final URL newMutatedUrl = new URL(url.getProtocol(), url.getHost(), Integer.valueOf(url.getPort()), parentPath + suffix);
                mutations.add(newMutatedUrl);
            }
        }

        return mutations;
    }

    private List<URL> createQueryMutations(final URL url) throws MalformedURLException {
        final List<URL> mutations = new ArrayList<>();
        final String path = url.getPath();

        for (final String suffix : QUERY_EXTENSIONS) {
            final URL newMutatedUrl = new URL(url.getProtocol(), url.getHost(), Integer.valueOf(url.getPort()), path + suffix);
            mutations.add(newMutatedUrl);
        }

        return mutations;
    }
}
