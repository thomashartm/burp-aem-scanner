package legacy.actions.dispatcher;

import burp.*;
import legacy.BurpHelperDto;
import legacy.Confidence;
import legacy.Severity;
import legacy.actions.AbstractDetector;
import legacy.payload.FilterEvasion;

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
        final String responseBody = responseBodyToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && responseBody.contains("jcr:primaryType");
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(GET_SERVLET_PATHS);
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
