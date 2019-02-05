package burp.actions.dispatcher;

import burp.*;
import burp.actions.SecurityCheck;
import burp.actions.WithHttpRequests;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Checks wether information is be exposed via AEM"s DefaultGetServlet.
 *
 * The burp extension is a port of 0ang3el's hacktivity conference checks.
 * See his presentation and the related aemhackers project
 * https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
 * https://github.com/0ang3el
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class GetServletExposed implements SecurityCheck, WithHttpRequests {

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

    private static final String PATH_PATTERN = "%s/%s";

    private final IHttpRequestResponse baseMessage;

    private final BurpHelperDto helperDto;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public GetServletExposed(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        this.helperDto = helperDto;
        this.baseMessage = baseMessage;
    }

    @Override
    public Boolean call() throws Exception {
        scan(baseMessage).forEach(iScanIssue -> this.helperDto.getCallbacks().addScanIssue(iScanIssue));
        return true;
    }

    private List<String> createUrlMutation(final IHttpService httpService) {
        final List<String> extensions = Arrays.asList(GET_SERVLET_EXTENSIONS);

        return Arrays.asList(GET_SERVLET_PATHS)
                .stream()
                .map(path -> extensions
                        .stream()
                        .map(extension -> String.format(PATH_PATTERN, path, extension))
                        .collect(Collectors.toList()))
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }

    @Override
    public List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse) {
        final IHttpService httpService = baseRequestResponse.getHttpService();

        final List<IScanIssue> issues = new ArrayList<>();
        createUrlMutation(httpService).forEach(path -> {
            try {
                final URL url = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), path);

                final IHttpRequestResponse requestResponse = this.sendRequest(url, httpService);

                final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
                final String responseBody = responseToString(requestResponse);

                this.helperDto.getCallbacks().printOutput("Request: " + url.toString() + " :: StatusCode: " + response.getStatusCode());
                if (response.getStatusCode() == 200 && responseBody.contains("jcr:primaryType")) {
                    report(requestResponse, ISSUE_NAME, String.format(ISSUE_DESCRIPTION, url.toString()))
                            .ifPresent(issue -> issues.add(issue));
                }
            } catch (MalformedURLException e) {
                this.helperDto.getCallbacks().printError("Unable to handle url for path " + path + " " + e);
            }
        });

        return issues;
    }

    public Optional<ScanIssue> report(IHttpRequestResponse requestResponse, final String name, final String description) {
        final ScanIssue.ScanIssueBuilder builder = createIssueBuilder(requestResponse, name, description);

        // start here and may add additional information depending on the statuscode.
        builder.withSeverity(Severity.HIGH);

        // success related status codes ... we need to look closely
        builder.withCertainConfidence();

        return Optional.of(builder.build());
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return this.helperDto.getHelpers();
    }

    @Override
    public BurpHelperDto getHelperDto() {
        return this.helperDto;
    }
}
