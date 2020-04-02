package legacy.actions.misconfiguration;

import burp.*;
import legacy.BurpHelperDto;
import legacy.Confidence;
import legacy.Severity;
import legacy.actions.AbstractDetector;
import legacy.payload.FilterEvasion;
import legacy.util.BurpHttpRequest;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Detects if the WCMSuggestionsServlet is exposed and potentially vulnerable.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class WcmSuggestionServletDetector extends AbstractDetector {

    private static final String ISSUE_NAME = "WCMSuggestionsServlet exposed";

    private static final String ISSUE_DESCRIPTION = "WCMSuggestionsServlet exposed and might result in reflected XSS. '\n"
            + "'See - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96";

    private static final String[] PATHS = new String[] {
            "/bin/wcm/contentfinder/connector/suggestions", "///bin///wcm///contentfinder///connector///suggestions"
    };

    private static final String QUERY_STRING = "query_term=path%3a/&pre=<1337abcdef>&post=yyyy";

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public WcmSuggestionServletDetector(BurpHelperDto helperDto, IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    /**
     * Overrides send request to toogle to a POST request
     *
     * @param url         Url
     * @param httpService http service
     * @return
     */
    public IHttpRequestResponse sendRequest(final URL url, final IHttpService httpService) {
        final BurpHttpRequest burpRequest = new BurpHttpRequest(getHelpers(), getBaseMessage(), url);
        burpRequest.setMethod("GET");
        burpRequest.addParameter("query_term", "path%3a/");
        burpRequest.addParameter("pre", "<1337abcdef>");
        burpRequest.addParameter("post", "yyyy");

        Optional<byte[]> newRequest = burpRequest.create();

        return getHelperDto().getCallbacks().makeHttpRequest(httpService, newRequest.get());
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseBodyToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && responseBody.contains("<1337abcdef>");
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(PATHS);
    }

    @Override
    protected List<String> getExtensions() {
        return FilterEvasion.ENUMERATION_EXTENSIONS.getBypasses();
    }

    @Override
    public String getName() {
        return ISSUE_NAME;
    }

    @Override
    public String getDescription() {
        return ISSUE_DESCRIPTION;
    }

    @Override
    public Severity getSeverity() {
        return severity;
    }

    @Override
    public Confidence getConfidence() {
        return confidence;
    }
}
