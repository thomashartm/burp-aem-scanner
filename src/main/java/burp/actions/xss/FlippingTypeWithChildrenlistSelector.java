package burp.actions.xss;

import burp.*;
import burp.actions.AbstractDetector;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class FlippingTypeWithChildrenlistSelector extends AbstractDetector {

    private static final String ISSUE_NAME = "XSS in childlist selector";

    private static final String ISSUE_DESCRIPTION = "Requests using the selector childlist can an XSS when the dispatcher does not respect the content-type " +
            "responded by AEM and flips from application/json to text/html. As a consequence the reflected suffix is executed and interpreted in the browser. " +
            "Make sure fix the dispatcher configuration to respect the real content-type and make sure the suffixes extension is not misinterpreted.";

    private static final String[] PATHS = new String[]{
            "/etc/designs/xh1x.childrenlist.json//<svg onload=alert(1)>.html"
    };

    private static final String IDENTIFIER = "<svg onload";

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    private String nameToReport;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public FlippingTypeWithChildrenlistSelector(BurpHelperDto helperDto, IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());

        // first we check wether the header Content-Type: text/html get's returned
        int contentTypeCounter = 0;
        boolean pass = false;
        for (final String header : response.getHeaders()) {
            // if we find the right content type then the XSS will trigger for browser with enabled flash
            if (!pass && StringUtils.startsWith(header, "Content-Type:")) {
                contentTypeCounter++;
                if (StringUtils.contains(header, "text/html")) {
                    getHelperDto().getCallbacks().printOutput("Found header: " + header);
                    pass = true;
                }
            }
        }

        // if content type is not set then FF will guess and trigger the XSS as the suffix has the extension .html
        if(!pass && contentTypeCounter == 0){
            pass = true;
        }

        final String responseBody = responseBodyToString(requestResponse);

        final boolean foundXssInBody = responseBody.contains(IDENTIFIER);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());
        getHelperDto().getCallbacks().printOutput("Xss in body: " + foundXssInBody);
        getHelperDto().getCallbacks().printOutput("Header: " + pass);
        return response.getStatusCode() == 200 && pass && responseBody.contains(IDENTIFIER);
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
        return String.format(ISSUE_NAME, nameToReport);
    }

    @Override
    public String getDescription() {
        return String.format(ISSUE_DESCRIPTION, nameToReport);
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