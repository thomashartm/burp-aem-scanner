package burp.actions.misconfiguration;

import burp.*;
import burp.actions.AbstractDetector;
import burp.util.BurpHttpRequest;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * WCMDebugFilter
 *
 * The burp extension is a port of 0ang3el's hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class DebugFilterDetector extends AbstractDetector {

    private static final String ISSUE_NAME = "WCMDebugFilter exposed";

    private static final String ISSUE_DESCRIPTION = "Sensitive information might be exposed via AEM 's WCMDebugFilter."
            + "It will render a backend interface which provides additional attack surface and might be vulnerable to reflected XSS (CVE-2016-7882). "
            + "See - https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c. "
            + "Please check the URL's manually. See %s";

    private static final String CELL_REFERENCE = "<br>cell=";

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public DebugFilterDetector(BurpHelperDto helperDto, IHttpRequestResponse baseMessage) {
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
        burpRequest.addParameter("debug", "layout");
        Optional<byte[]> newRequest = burpRequest.create();

        return getHelperDto().getCallbacks().makeHttpRequest(httpService, newRequest.get());
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseBodyToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && responseBody.contains(CELL_REFERENCE);
    }

    @Override
    protected List<String> getPaths() {
        final URL baseUrl = getHelpers().analyzeRequest(getBaseMessage().getHttpService(), getBaseMessage().getRequest()).getUrl();
        return Arrays.asList(baseUrl.getPath());
    }

    @Override
    protected List<String> getExtensions() {
        return Collections.emptyList();
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
