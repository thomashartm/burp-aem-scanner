package burp.actions.dispatcher;

import burp.*;
import burp.actions.AbstractUriListDetector;
import burp.actions.BurpHttpRequest;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Checks wether the post servlet is exposed and write access is potentially possible.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class PostServletExposed extends AbstractUriListDetector {

    private static final String ISSUE_NAME = "PostServlet exposed";

    private static final String ISSUE_DESCRIPTION = "PostServlet is exposed. "
            + "It might be possible to post a stored XSS payload resource which are writeable for the current user."
            + "Nodes such as /content/usergenerated/etc/commerce/smartlists are writeable (jcr:write) for anonymous users";

    private static final String[] PATHS = new String[] {
            "/", "/content", "/content/dam"
    };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public PostServletExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
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

        burpRequest.setBody(":operation=nop");
        burpRequest.addHeader("Content-Type: application/x-www-form-urlencoded");
        burpRequest.addHeader(String.format("Referer: %s", getBaseUrl(url)));
        Optional<byte[]> newRequest = burpRequest.create();

        return getHelperDto().getCallbacks().makeHttpRequest(httpService, newRequest.get());
    }

    private String getBaseUrl(final URL url) {
        final String protocol = url.getHost();
        final String host = url.getHost();
        final String port = url.getPort() == 80 || url.getPort() == 443 ? "" : ":" + url.getPort();

        return String.format("%s://%s%s%s", protocol, host, port, url.getPath());
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && StringUtils.contains(responseBody, "Null Operation Status:");
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
