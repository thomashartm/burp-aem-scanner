package burp;

import org.apache.commons.lang3.StringUtils;

import java.net.URL;

/**
 * Extends the {@link IScannerCheck} and makes sure that consuming scanners are able to consolidate issues.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public interface ConsolidatingScanner extends IScannerCheck {

    /**
     * Compares issues to find duplicates.
     *
     * @param existingIssue The existing issue
     * @param newIssue      The new issues
     * @return Lower then 0 if the issues are the same.
     */
    default int consolidateDuplicateIssues(final IScanIssue existingIssue, final IScanIssue newIssue) {
        final boolean areSameIssues = existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail()
                .equals(newIssue.getIssueDetail());
        return areSameIssues ? -1 : 0;
    }

    default ScanIssue.ScanIssueBuilder createIssueBuilder(final IHttpRequestResponse baseRequestResponse, final String name, final String details) {
        final IRequestInfo request = getHelpers()
                .analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
        final URL url = request.getUrl();
        final ScanIssue.ScanIssueBuilder builder = ScanIssue.ScanIssueBuilder.aScanIssue();
        builder.withUrl(url);

        builder.withHttpMessages(new IHttpRequestResponse[] { baseRequestResponse });
        builder.withHttpService(baseRequestResponse.getHttpService());

        builder.withName(name);
        builder.withDetail(details);
        return builder;
    }

    IExtensionHelpers getHelpers();
}
