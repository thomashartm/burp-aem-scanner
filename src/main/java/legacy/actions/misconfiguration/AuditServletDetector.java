package legacy.actions.misconfiguration;

import burp.*;
import legacy.BurpHelperDto;
import legacy.Confidence;
import legacy.Severity;
import legacy.actions.AbstractDetector;
import legacy.payload.FilterEvasion;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.List;

/**
 * Checks wether the audit log servlet is accessible and if it exposed any auditlog results.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class AuditServletDetector extends AbstractDetector {

    private static final String ISSUE_NAME = "AuditServletDetector exposed";

    private static final String ISSUE_DESCRIPTION = "AuditServletDetector exposed and might expose audit log information. "
            + "See https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96";

    private static final String[] PATHS = new String[] {
            "/bin/msm/audit", "///bin///msm///audit"
    };

    private static final Severity severity = Severity.HIGH;

    private static final Confidence confidence = Confidence.CERTAIN;

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param helperDto
     * @param baseMessage
     */
    public AuditServletDetector(BurpHelperDto helperDto, IHttpRequestResponse baseMessage) {
        super(helperDto, baseMessage);
    }

    @Override
    protected boolean issueDetected(IHttpRequestResponse requestResponse) {
        final IResponseInfo response = getHelpers().analyzeResponse(requestResponse.getResponse());
        final String responseBody = responseBodyToString(requestResponse);

        getHelperDto().getCallbacks().printOutput("StatusCode: " + response.getStatusCode());

        if (response.getStatusCode() == 200) {
            final String body = responseBodyToString(requestResponse);
            final JSONObject json = new JSONObject(body);
            return json.has("results") && json.getLong("results") > 0;
        }
        return false;
    }

    @Override
    protected List<String> getPaths() {
        return Arrays.asList(PATHS);
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
