package burp.actions.accesscontrol;

import burp.*;
import burp.actions.AbstractUriListDetector;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Another sling post related issue, checking wether we can write to user generated content and create our own testnodes
 * <p>
 * Testing the possibility to write to the repository using an anonymous session is part of the AEM secuirty checklist.
 * See https://helpx.adobe.com/experience-manager/dispatcher/using/dispatcher-configuration.html
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class WriteAccessPossible extends AbstractUriListDetector {

    private static final String ISSUE_NAME = "Anonymous write access is enabled";

    private static final String ISSUE_DESCRIPTION = "PostServlet is exposed and anonymous write access is possible. "
            + "It might be possible to post a stored XSS payload resource which are writeable for the current user.";

    private static final String[] PATHS = new String[] {
            "/content/usergenerated/mytestnode"
    };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public WriteAccessPossible(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
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

        byte[] baseGetRequest = getHelpers().buildHttpRequest(url);
        byte[] postRequest = getHelpers().toggleRequestMethod(baseGetRequest);

        return getHelperDto().getCallbacks().makeHttpRequest(httpService, postRequest);
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200;
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(PATHS);
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
