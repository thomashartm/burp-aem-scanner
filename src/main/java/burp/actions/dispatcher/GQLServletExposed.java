package burp.actions.dispatcher;

import burp.*;
import burp.actions.AbstractUriListDetector;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Checks wether sensitive information is exposed via AEM"s GQLServlet.
 * <p>
 * The burp extension is a port of 0ang3el"s hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class GQLServletExposed extends AbstractUriListDetector {

    private static final String ISSUE_NAME = "GQLServletExposed metadata exposure";

    private static final String ISSUE_DESCRIPTION = "Sensitive information might be exposed via AEM 's GQLServletExposed.";

    private static final String[] GET_SERVLET_PATHS = new String[] {
            "/bin/wcm/search/gql.servlet.json?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.1.json?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.4.2.1...json?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json;%0aa.css?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json;%0aa.html?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json;%0aa.js?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json;%0aa.png?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json;%0aa.ico?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.css?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.js?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.ico?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.png?query=type:base%20limit:..1&pathPrefix=",
            "/bin/wcm/search/gql.json/a.html?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.servlet.json?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.1.json?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.4.2.1...json?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json;%0aa.css?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json;%0aa.js?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json;%0aa.html?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json;%0aa.png?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json;%0aa.ico?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.css?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.ico?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.png?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.js?query=type:base%20limit:..1&pathPrefix=",
            "///bin///wcm///search///gql.json///a.html?query=type:base%20limit:..1&pathPrefix="
    };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public GQLServletExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
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
        return Arrays.asList(GET_SERVLET_PATHS);
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