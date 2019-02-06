package burp.actions.dispatcher;

import burp.*;
import burp.actions.AbstractUriListDetector;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;

/**
 * Checks wether QueryBuilder related servlets expose sensitive information.
 * <p>
 * The burp extension is a port of 0ang3el's hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class QueryBuilderExposed extends AbstractUriListDetector {

    private static final String ISSUE_NAME = "QueryBuilder exposure";

    private static final String ISSUE_DESCRIPTION =
            "Sensitive information might be exposed via AEMs QueryBuilderServlet or QueryBuilderFeedServlet."
                    + "%s";

    private static final String[] SERVLET_PATHS = new String[] {
            "/bin/querybuilder.json", "/bin/querybuilder.json.servlet",
            "///bin///querybuilder.json", "///bin///querybuilder.json.servlet",
            "/bin/querybuilder.feed", "/bin/querybuilder.feed.servlet",
            "///bin///querybuilder.feed", "///bin///querybuilder.feed.servlet"
    };

    private static final String[] EXTENSIONS = new String[] {
            "", ".css", ".ico", ".png", ".gif", ".jpeg", ".html", ".1.json", ".4.2.1...json",
            "/a.css", "/a.html", "/a.ico", "/a.png", "/a.js", "/a.1.json", "/a.4.2.1...json",
            ";%0aa.css", ";%0aa.png", ";%0aa.js", ";%0aa.html", ";%0aa.ico"
    };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public QueryBuilderExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && StringUtils.containsAny(responseBody, "hits", "<feed>");
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(SERVLET_PATHS);
    }

    @Override
    protected List<String> getExtensions() {
        return Arrays.asList(EXTENSIONS);
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
