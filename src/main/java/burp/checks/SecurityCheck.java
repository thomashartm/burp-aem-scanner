package burp.checks;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.WithIssueBuilder;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * Custom scanner implementation that executes a security check on the given base response parameter.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface SecurityCheck extends WithIssueBuilder, Callable<Boolean> {

    /**
     * Executes the scan. Can be run outside of the active or passive scanner as we need to be able to execute exactly once only.
     * @param baseRequestResponse
     * @return
     */
    List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse);

    /**
     * Upper and lower bound status code checks
     *
     * @param value      Current value
     * @param lowerBound lower bound
     * @param upperBound upper bound
     * @return True if within.
     */
    default boolean isInRange(short value, int lowerBound, int upperBound) {
        final Integer intval = Integer.valueOf(value);
        return lowerBound <= intval && intval <= upperBound;
    }
}
