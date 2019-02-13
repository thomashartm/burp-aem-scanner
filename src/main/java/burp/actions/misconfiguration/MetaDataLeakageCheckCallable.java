package burp.actions.misconfiguration;

import burp.*;
import burp.actions.SecurityCheck;
import burp.util.BurpHttpRequest;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * Verfies the provides URLs by appending a set of extensions and checks wether the requested URLs expose confidential information such as usernames.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 * @deprecated will be replaced by a more lean version
 */
public class MetaDataLeakageCheckCallable implements SecurityCheck {

    private static final String ISSUE_NAME = "AEM default renderers enabled.";

    private static final String ISSE_DETAILS = "The page is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block access to any URL that leaks metadata. Currently it responds with statuscode 200 for URl %s";

    public static final String ERROR_PAGE_INFO_LEAKAGE = "Server platform information disclosed";

    private static final String ERROR_PAGE_INFO_DETAILS = "The error pages leaks information about the platform/runtime environment. See %s";

    private static final String CONFIDENTIAL_DATA_LEAKAGE = "Authentication information leakage";

    private static final String CONFIDENTIAL_DATA_LEAKAGE_DETAILS = "Username or credential information leaked. Please check the response for JCR properties whoch should be kept private. Found property %s with value %s in response.";

    private static final String[] CONTENT_GRAPPING_SUFFIXES = new String[] {
            "xxyzkgv.html", ".tidy.-100.json", ".-1.json", ".infinity.json", ".1.json", ".10.json", ".tidy.blubber.json", ".blubber.json",
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

    private static final String[] CREDENTIAL_JCR_PROPERTIES = new String[] { "jcr:createdBy", "jcr:lastModifiedBy", "rep:principalName",
            "rep:password", "rep:authorizableId" };

    private final BurpHelperDto helperDto;

    private final IHttpRequestResponse baseMessage;

    public MetaDataLeakageCheckCallable(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        this.helperDto = helperDto;
        this.baseMessage = baseMessage;
    }

    @Override
    public Boolean call() throws Exception {
        final List<IScanIssue> issues = scan(baseMessage);
        issues.forEach(iScanIssue -> this.helperDto.getCallbacks().addScanIssue(iScanIssue));
        return true;
    }

    @Override
    public List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse) {

        this.helperDto.getCallbacks().printOutput("MetaDataLeakageCheckCallable call submitted for execution");
        // always use the http service as we else get an unsupported operation exception under the hoods
        final IHttpService httpsService = baseRequestResponse.getHttpService();
        final IRequestInfo baseRequest = this.helperDto.getHelpers().analyzeRequest(httpsService, baseRequestResponse.getRequest());
        final URL aemPageUrl = baseRequest.getUrl();

        try {
            final List<URL> mutations = new ArrayList<>();
            mutations.addAll(createSuffixMutations(aemPageUrl));
            mutations.addAll(createPathMutations(aemPageUrl));
            mutations.addAll(createQueryMutations(aemPageUrl));

            final IHttpService httpService = baseRequestResponse.getHttpService();
            return scanUrlMutations(httpService, aemPageUrl, mutations);
        } catch (MalformedURLException e) {
            this.helperDto.getCallbacks().printError("URL is malformed. " + e);
        }
        return Collections.emptyList();
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

    private List<IScanIssue> scanUrlMutations(final IHttpService httpService, final URL baseAemUrl, final List<URL> mutations) {
        final List<IScanIssue> results = new ArrayList<>();
        this.helperDto.getCallbacks().printOutput(String.format("Metadata check for mutations %s ", StringUtils.join(mutations, ";")));
        for (final URL mutation : mutations) {

            final byte[] request = this.helperDto.getHelpers().buildHttpRequest(mutation);
            IHttpRequestResponse requestResponse = this.helperDto.getCallbacks().makeHttpRequest(httpService, request);

            final IResponseInfo responseInfo = this.helperDto.getHelpers().analyzeResponse(requestResponse.getResponse());
            final short statusCode = responseInfo.getStatusCode();

            if (isInRange(statusCode, 200, 302)) {
                this.helperDto.getCallbacks()
                        .printOutput(String.format("Metadata check for mutation %s had a positive match", mutation.toString()));
                // we have metadata leakage anyway ...
                results.add(createMetadataLeakageIssue(requestResponse, baseAemUrl, mutation));

                // now we check if we leak any credentials for the JSON renditions of our pages
                if (mutation.toString().contains(".json")) {
                    final List<IScanIssue> credentialIssues = checkForCredentialLeakage(requestResponse);
                    if (credentialIssues.size() > 0) {
                        results.addAll(credentialIssues);
                    }
                }

            } else if (isInRange(statusCode, 400, 500)) {
                this.helperDto.getCallbacks()
                        .printOutput(String.format("Error leakage check for mutation %s had a positive match", mutation.toString()));
                checkForDataLeakage(requestResponse).ifPresent(iScanIssue -> results.add(iScanIssue));
            }
        }
        return results;
    }

    private List<IScanIssue> checkForCredentialLeakage(final IHttpRequestResponse requestResponse) {
        final String responseMessage = this.helperDto.getHelpers().bytesToString(requestResponse.getResponse());

        final List<IScanIssue> results = new ArrayList<>();

        final byte[] response = requestResponse.getResponse();
        final IResponseKeywords keywords = this.helperDto.getHelpers()
                .analyzeResponseKeywords(Arrays.asList(CREDENTIAL_JCR_PROPERTIES), response);

        for (final String property : CREDENTIAL_JCR_PROPERTIES) {
            final int keywordCount = keywords.getKeywordCount(property, 0);
            if(keywordCount > 0){
                final String details = String.format(CONFIDENTIAL_DATA_LEAKAGE_DETAILS, property, 0);

                final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, CONFIDENTIAL_DATA_LEAKAGE, details);
                final IRequestInfo requestInfo = this.helperDto.getHelpers()
                        .analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
                builder.withUrl(requestInfo.getUrl());
                builder.withSeverityHigh();
                builder.withCertainConfidence();

                results.add(builder.build());
            }
        }
        return results;
    }

    private Optional<String> extractRelevantSnippet(final IHttpRequestResponse requestResponse, final String keyword,
            int count) {
        IExtensionHelpers helpers = this.helperDto.getHelpers();
        final byte[] response = requestResponse.getResponse();
        final IResponseInfo responseInfo = helpers.analyzeResponse(response);

        byte[] keywordBytes = keyword.getBytes();
        int indexPos = responseInfo.getBodyOffset();
        for(int i = 0; i < count; i++){
            int keywordIndex = helpers.indexOf(response, keywordBytes, false, indexPos, response.length);
            indexPos = indexPos + keywordIndex;
            // first we get a bigger slice then we slimm it down
            byte[] keywordSlice = Arrays.copyOfRange(response, keywordIndex, indexPos + 100);
            final String keywordline = helpers.bytesToString(keywordSlice);
            final int nextDelimiterIndex = StringUtils.indexOfAny(keywordline, "\n", ",", "\",", "}");

            final String value = StringUtils.substring(keywordline, 0, nextDelimiterIndex);
            return Optional.of(value);
        }

        return Optional.empty();
    }

    private IScanIssue createMetadataLeakageIssue(final IHttpRequestResponse requestResponse, final URL baseAemUrl, final URL mutation) {
        // AEM is responding to the message, now we need to evaluate the response
        final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, ISSUE_NAME,
                String.format(ISSE_DETAILS, mutation.toString()));
        // we use the original URL as we else spam the target tree with all mutations.
        builder.withUrl(baseAemUrl);
        builder.withSeverityMedium();
        builder.withCertainConfidence();
        return builder.build();
    }

    private Optional<IScanIssue> checkForDataLeakage(final IHttpRequestResponse requestResponse) {
        final String responseMessage = this.helperDto.getHelpers().bytesToString(requestResponse.getResponse());
        final String[] addresses = StringUtils.substringsBetween(responseMessage, "<address>", "</address>");

        if (addresses != null && addresses.length > 0) {
            final String details = String.format(ERROR_PAGE_INFO_DETAILS, StringUtils.join(addresses, ","));
            final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, ERROR_PAGE_INFO_LEAKAGE, details);
            // for now it is only information

            final IRequestInfo requestInfo = this.helperDto.getHelpers()
                    .analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());

            builder.withUrl(requestInfo.getUrl());
            builder.withSeverityLow();
            builder.withCertainConfidence();
            return Optional.of(builder.build());
        }

        return Optional.empty();
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
        final String path = url.getPath();
        final int indexOfLastSlash = path.lastIndexOf("/");
        if (indexOfLastSlash > 0) {
            final String parentPath = StringUtils.substringBeforeLast(path, "/");
            return createMutation(url, parentPath, CONTENT_GRAPPING_PATH_ELEMENTS);
        }

        return Collections.emptyList();
    }

    private List<URL> createQueryMutations(final URL url) throws MalformedURLException {
        return createMutation(url, url.getPath(), QUERY_EXTENSIONS);
    }

    private List<URL> createMutation(URL url, String path, String[] queryExtensions) throws MalformedURLException {
        final List<URL> mutations = new ArrayList<>();
        for (final String suffix : queryExtensions) {
            final URL newMutatedUrl = new URL(url.getProtocol(), url.getHost(), Integer.valueOf(url.getPort()), path + suffix);
            mutations.add(newMutatedUrl);
        }

        return mutations;
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helperDto.getHelpers();
    }

    @Override public IHttpRequestResponse sendRequest(URL url, IHttpService httpService) {
        return null;
    }

    @Override public BurpHelperDto getHelperDto() {
        return null;
    }
}
