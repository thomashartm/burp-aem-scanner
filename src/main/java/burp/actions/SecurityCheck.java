package burp.actions;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.util.WithIssueBuilder;
import burp.util.WithComparator;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * Custom scanner implementation that executes a security check on the given base response parameter.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface SecurityCheck extends WithIssueBuilder, WithComparator, Callable<Boolean> {

    /**
     * Executes the scan. Can be run outside of the active or passive scanner as we need to be able to execute exactly once only.
     * @param baseRequestResponse
     * @return
     */
    List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse);
}
