package burp.actions.dispatcher;

import burp.*;
import burp.actions.AbstractDetector;

import java.util.Arrays;
import java.util.List;

/**
 * Checks wether information is be exposed via AEM"s DefaultGetServlet.
 * <p>
 * The burp extension is a port of 0ang3el's hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class GetServletExposed extends AbstractDetector {

    private static final String ISSUE_NAME = "DefaultGetServlet metadata exposure";

    private static final String ISSUE_DESCRIPTION = "Sensitive information might be exposed via AEM 's DefaultGetServlet. "
            + "Please check the URL's manually. See %s";

    private static final String[] GET_SERVLET_PATHS = new String[] {
            "/etc", "/var", "/apps", "/home", "///etc", "///var", "///apps", "///home"
    };

    private static final String[] GET_SERVLET_EXTENSIONS = new String[] {
            ".json", ".1.json", ".4.2.1....json", ".json/a.css", ".json.html", ".json.css",
            ".json/a.html", ".json/a.png", ".json/a.ico", ".json/b.jpeg", ".json/b.gif",
            ".json;%0aa.css", ".json;%0aa.png", ".json;%0aa.html", ".json;%0aa.js", ".json/a.js"
    };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public GetServletExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && responseBody.contains("jcr:primaryType");
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
        return severity;
    }

    @Override
    public Confidence getConfidence() {
        return confidence;
    }
}
