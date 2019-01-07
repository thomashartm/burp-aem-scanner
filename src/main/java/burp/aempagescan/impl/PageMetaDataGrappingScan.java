package burp.aempagescan.impl;

import burp.*;
import burp.aempagescan.ActiveAemPageScan;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
public class PageMetaDataGrappingScan implements ActiveAemPageScan, WithStatusCode, WithIssueBuilder {

    private static final String ISSUE_NAME = "AEM default renderers enabled.";

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

    private final IBurpExtenderCallbacks callbacks;

    private final IExtensionHelpers helpers;

    public PageMetaDataGrappingScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> scan(IHttpRequestResponse baseRequestResponse, URL aemPageUrl) {
        try {
            final List<URL> mutations = new ArrayList<>();
            mutations.addAll(createSuffixMutations(aemPageUrl));
            mutations.addAll(createPathMutations(aemPageUrl));
            mutations.addAll(createQueryMutations(aemPageUrl));

            final IHttpService httpService = baseRequestResponse.getHttpService();
            return scanUrlMutations(httpService, aemPageUrl, mutations);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return Collections.emptyList();
    }

    public List<IScanIssue> scanUrlMutations(final IHttpService httpService, final URL baseAemUrl, final List<URL> mutations) {
        final List<IScanIssue> results = new ArrayList<>();
        for (final URL mutation : mutations) {
            final byte[] request = this.helpers.buildHttpRequest(mutation);
            IHttpRequestResponse requestResponse = this.callbacks.makeHttpRequest(httpService, request);

            final IResponseInfo responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
            final short statusCode = responseInfo.getStatusCode();

            if (statusCode != 404) {
                // AEM is responding to the message, now we need to evaluate the response
                final String details = String
                        .format("The page %s is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block the mutation %s. Currently it responds with statuscode %s",
                                baseAemUrl.toString(), mutation.toString(), String.valueOf(statusCode));
                final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, ISSUE_NAME, details);

                // we use the original URL as we else spam the target tree with all mutations.
                builder.withUrl(baseAemUrl);

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
        return results;
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

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helpers;
    }
}
