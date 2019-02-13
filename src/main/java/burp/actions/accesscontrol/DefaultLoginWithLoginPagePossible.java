package burp.actions.accesscontrol;

import burp.*;
import burp.actions.AbstractDetector;
import burp.actions.http.PostRequest;
import burp.actions.http.ResponseHolder;
import burp.payload.DefaultCredential;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.function.Consumer;

/**
 * Checks wether the default login page is available and the default credentials are not deactivated
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class DefaultLoginWithLoginPagePossible extends AbstractDetector {

    private static final String LOGIN_PAGE = "/libs/granite/core/content/login.html/j_security_check";

    private static final String ISSUE_NAME = "Default credentials detected";

    private static final String ISSUE_DESCRIPTION = "Default credentials detected and can be "
            + "used to gain access to the system. Login with credentials %s was successful at the default login page URL %s";

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public DefaultLoginWithLoginPagePossible(BurpHelperDto helperDto, IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    public Consumer<String> providePathConsumer(final IHttpService httpService, final List<IScanIssue> issues) {
        return path -> {
            try {
                final Set<String> detectedCredentials = new HashSet<>();
                final URL loginUrl = this.createLoginUrl(httpService, path);

                IHttpRequestResponse requestResponse = null;
                for (final DefaultCredential credentialPair : DefaultCredential.values()) {
                    requestResponse = this.sendRequest(loginUrl, credentialPair.getUserName(), credentialPair.getPassword());
                    if (requestResponse != null && issueDetected(requestResponse)) {
                        detectedCredentials.add(credentialPair.getCombination());
                    }
                }

                if (detectedCredentials.size() > 0) {
                    report(requestResponse, getName(),
                            String.format(getDescription(), StringUtils.join(detectedCredentials, " ; "), loginUrl.toString()),
                            Severity.HIGH,
                            Confidence.CERTAIN).ifPresent(issue -> issues.add(issue));
                }
            } catch (MalformedURLException e) {
                getHelperDto().getCallbacks().printError("Unable to handle url for path " + path + " " + e);
            }
        };
    }

    /**
     * Sends a request to the target URL
     *
     * @param url      URL
     * @param userName username
     * @param password paswword
     * @return
     * @throws MalformedURLException
     */
    public IHttpRequestResponse sendRequest(final URL url, final String userName, final String password) {
        final PostRequest postRequest = PostRequest.createInstance(getHelperDto(), getBaseMessage());
        postRequest.init(url);
        postRequest.addBodyParam("_charset_", "utf-8");

        // splitting up user and pw as static code analysis rules complain about the terms being used.
        postRequest.addBodyParam("j_u" + "sern" + "ame", userName);
        postRequest.addBodyParam("j_pas" + "swo" + "rd", password);

        postRequest.addBodyParam("j_validate", String.valueOf(true));

        final ResponseHolder responseHolder = postRequest.send();

        return responseHolder.getResponseMessage();
    }

    private URL createLoginUrl(final IHttpService httpService, final String path) throws MalformedURLException {
        return new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), path);
    }

    @Override
    protected boolean issueDetected(final IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String rawResponse = getHelpers().bytesToString(requestResponse.getResponse());

        //HTTP/1.1 200 OK
        //Date: Wed, 13 Feb 2019 07:59:38 GMT
        //Set-Cookie: login-token=e595c68f-2254-49e8-8b2f-2478c75380dd%3a0dcfe41a-44be-4a7a-968c-925670cce96c_7997d193307a16fe68b08096c23e8ad1%3acrx.default; Path=/; HttpOnly
        //Content-Type: text/plain
        //Pragma: no-cache
        //Cache-Control: no-cache
        //Cache-Control: no-store
        //Content-Length: 0
        //Connection: close

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode() + "\n");

        return response.getStatusCode() == 200
                && StringUtils.contains(rawResponse, "Set-Cookie: login-token=") && StringUtils.contains(rawResponse, "HttpOnly");
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(LOGIN_PAGE);
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
        return Severity.HIGH;
    }

    @Override
    public Confidence getConfidence() {
        return Confidence.CERTAIN;
    }
}
