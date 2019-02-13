package burp.actions;

import burp.Confidence;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.Severity;
import burp.util.WithComparator;
import burp.util.WithIssueBuilder;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * Custom scanner implementation that executes a security check on the given base response parameter.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface SecurityCheck extends WithHttpRequests, WithIssueBuilder, WithComparator, Callable<Boolean> {

    String PATH_PATTERN = "%s%s";

    /**
     * Executes the scan. Can be run outside of the active or passive scanner as we need to be able to execute exactly once only.
     *
     * @param baseRequestResponse
     * @return List of IScanIssues
     */
    List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse);

    /**
     * Provides the issue name which serves as an identifier
     *
     * @return String
     */
    String getName();

    /**
     * Provides the description which is shown in the issue.
     *
     * @return String
     */
    String getDescription();

    /**
     * Provides the {@link Severity}
     *
     * @return Severity
     */
    Severity getSeverity();

    /**
     * Provides the {@link Confidence}
     *
     * @return Confidence
     */
    Confidence getConfidence();
}
