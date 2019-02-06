package burp.actions.dispatcher;

import burp.*;
import burp.actions.AbstractDetector;
import burp.util.BurpHttpRequest;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * Checks wether the LoginStatusServlet is exposed.
 * <p>
 * The burp extension is a port of 0ang3el"s hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class LoginStatusServletExposed extends AbstractDetector {

    private static final String ISSUE_NAME = "LoginStatusServlet exposure";

    private static final String ISSUE_DESCRIPTION =
            "LoginStatusServlet is exposed, it allows to bruteforce credentials. "
                    + "Enumerate valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:lastModifiedBy attributes of any JCR node. See GetServletExposed check.";

    private static final String DEFAULT_AUTH_ISSUE_NAME = "AEM Default Credentials detected";

    private static final String DEFAULT_AUTH_ISSUE_DESCRIPTION =
            "Default credentials detected and can be used to gain access to the system. Credentials found: %s";

    private static final String[] SERVLET_PATHS = new String[] {
            "/system/sling/loginstatus", "///system///sling///loginstatus"
    };

    private static final String[] EXTENSIONS = new String[] {
            "",".json", ".css", ".ico", ".png", ".gif", ".html", ".js", ".json/a.1.json",
            ".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.js", ".json;%0aa.png",
            ".json;%0aa.ico", ".4.2.1...json"
    };

    private static final String[] DEFAULT_CREDENTIALS = new String[] {
            "admin:admin", "author:author", "replication-receiver:replication-receiver", "vgnadmin:vgnadmin",
            "aparker@geometrixx.info:aparker", "jdoe@geometrixx.info:jdoe"
    };

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public LoginStatusServletExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    public Consumer<String> providePathConsumer(final IHttpService httpService, final List<IScanIssue> issues) {
        return path -> {
            try {
                final URL url = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), path);
                final IHttpRequestResponse requestResponse = this.sendRequest(url, httpService);

                getHelperDto().getCallbacks().printOutput("Request: " + url);
                if (issueDetected(requestResponse)) {

                    report(requestResponse, getName(),
                            String.format(getDescription(), url.toString()),
                            Severity.HIGH,
                            Confidence.CERTAIN)
                            .ifPresent(issue -> issues.add(issue));

                    this.checkForDefaultCredentialAuthentication(url, issues);
                }
            } catch (MalformedURLException e) {
                getHelperDto().getCallbacks().printError("Unable to handle url for path " + path + " " + e);
            }
        };
    }

    private void checkForDefaultCredentialAuthentication(final URL url, final List<IScanIssue> issues) {
        for (final String credentialPair : DEFAULT_CREDENTIALS) {
            final String authorizationHeader = String.format("Authorization: Basic %s", getHelpers().base64Encode(credentialPair));
            final BurpHttpRequest burpRequest = new BurpHttpRequest(getHelpers(), getBaseMessage(), url);
            burpRequest.setMethod("GET");
            burpRequest.addHeader(authorizationHeader);

            final IHttpRequestResponse authRequestResponse = this.sendRequest(burpRequest, getBaseMessage().getHttpService());
            final String responseBody = responseToString(authRequestResponse);
            if (StringUtils.contains(responseBody, "authenticated")) {
                report(authRequestResponse,
                        DEFAULT_AUTH_ISSUE_NAME,
                        String.format(DEFAULT_AUTH_ISSUE_DESCRIPTION, credentialPair),
                        Severity.HIGH,
                        Confidence.CERTAIN)
                        .ifPresent(issue -> issues.add(issue));
            }
        }
    }

    @Override
    protected boolean issueDetected(final IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        return response.getStatusCode() == 200 && StringUtils.contains(responseBody, "authenticated");
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
        return Severity.HIGH;
    }

    @Override
    public Confidence getConfidence() {
        return Confidence.CERTAIN;
    }
}
