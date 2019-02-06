package burp.actions;

import burp.*;
import burp.util.WithComparator;
import burp.util.WithIssueBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

/**
 * Custom scanner implementation that executes a security check on the given base response parameter.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface SecurityCheck extends WithIssueBuilder, WithComparator, Callable<Boolean> {

    String PATH_PATTERN = "%s%s";

    /**
     * Executes the scan. Can be run outside of the active or passive scanner as we need to be able to execute exactly once only.
     *
     * @param baseRequestResponse
     * @return
     */
    List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse);

    String getName();

    String getDescription();

    Severity getSeverity();

    Confidence getConfidence();
}
