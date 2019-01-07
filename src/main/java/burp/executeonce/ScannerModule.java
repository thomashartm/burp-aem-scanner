package burp.executeonce;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.WithIssueBuilder;

import java.util.List;

/**
 * ScannerModule
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface ScannerModule extends WithIssueBuilder {

    /**
     *
     * @param baseRequestResponse
     * @return
     */
    List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse);
}
