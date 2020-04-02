package legacy.actions.crx;

import burp.*;
import legacy.BurpHelperDto;
import legacy.Confidence;
import legacy.Severity;
import legacy.actions.AbstractDetector;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Checks wether crx is accessible. All CRX related backends are highly critical and can be used to
 * enumerate sensitive information and to inject, install and/or execute custom code.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class CrxExposedDetector extends AbstractDetector {

    private static final String ISSUE_NAME = "Repository backend %s is exposed";

    private static final String ISSUE_DESCRIPTION =
            "Critical content repository backend %s is exposed and it is possible to bruteforce into it. "
                    + "Access to this backend tool must be restricted by any means as opens up a complete set of potential vulnerabilities."
                    + "All CRX related backends are highly critical and can be used to enumerate sensitive information and to inject, install and/or execute custom code. ";

    private static final String[] PATHS = new String[] {
            "/crx/de/index.jsp", "///crx///de///index.jsp", "/crx/explorer/browser/index.jsp",
            "///crx///explorer///browser///index.jsp",
            "/crx/packmgr/index.jsp", "///crx///packmgr///index.jsp"
    };

    private static final String[] IDENTIFIERS = new String[] { "CRXDE Lite", "Content Explorer", "CRX Package Manager" };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    private String nameToReport;

    /**
     * Constructor
     *
     * @param helperDto
     * @param baseMessage
     */
    public CrxExposedDetector(final BurpHelperDto helperDto, final IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());
        final String responseBody = responseBodyToString(requestResponse);
        boolean matchDetected = false;
        if (response.getStatusCode() == 200) {

            Optional<String> match = Arrays.asList(IDENTIFIERS).stream().filter(item -> StringUtils.contains(responseBody, item))
                    .findAny();

            if (match.isPresent()) {
                matchDetected = true;
                nameToReport = match.get();
            }
        }
        return matchDetected;
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
