package burp.actions.dispatcher;

import burp.*;
import burp.actions.AbstractDetector;
import burp.util.BurpHttpRequest;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Checks if the system console is accessible and providing attack surface.
 *
 * The burp extension is a port of 0ang3el's hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class FelixSystemConsoleExposed extends AbstractDetector {

    private static final String ISSUE_NAME = "Potential RCE through exposed Felix console";

    private static final String ISSUE_DESCRIPTION =
            "The Felix console is exposed. It is an administrative backend which provides full access to the AEM installation and allows to install own code."
                    + "Potential Remote Code Execution vulnerabilty.";

    private static final String[] GET_SERVLET_PATHS = new String[] {
            "/system/console/bundles", "///system///console///bundles"
    };

    private static final String[] GET_SERVLET_EXTENSIONS = new String[] {
            "", ".json", ".1.json", ".4.2.1...json", ".css", ".ico", ".png", ".gif", ".html", ".js",
            ";%0aa.css", ";%0aa.html", ";%0aa.js", ";%0aa.png", ".json;%0aa.ico", ".servlet/a.css",
            ".servlet/a.js", ".servlet/a.html", ".servlet/a.ico", ".servlet/a.png"
    };

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public FelixSystemConsoleExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    public IHttpRequestResponse sendRequest(final URL url, final IHttpService httpService) {
        final BurpHttpRequest burpRequest = new BurpHttpRequest(getHelpers(), getBaseMessage(), url);
        burpRequest.setMethod("GET");
        burpRequest.addHeader("Authorization: Basic YWRtaW46YWRtaW4=");
        Optional<byte[]> newRequest = burpRequest.create();

        return getHelperDto().getCallbacks().makeHttpRequest(httpService, newRequest.get());
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseBodyToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && responseBody.contains("Web Console");
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(GET_SERVLET_PATHS);
    }

    @Override
    protected List<String> getExtensions() {
        return Arrays.asList(GET_SERVLET_EXTENSIONS);
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
        return Severity.HIGH;
    }

    @Override
    public Confidence getConfidence() {
        return Confidence.CERTAIN;
    }
}
