package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Provides support of the issue builder to create @{@link IScanIssue}s
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface WithIssueBuilder {

    default ScanIssue.ScanIssueBuilder createIssueBuilder(final IHttpRequestResponse baseRequestResponse, final String name,
            final String details) {
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

    default List<IScanIssue> toList(IScanIssue... scanIssues) {
        final List<IScanIssue> issues = new ArrayList<IScanIssue>();
        issues.addAll(Arrays.asList(scanIssues));
        return issues;
    }
}
