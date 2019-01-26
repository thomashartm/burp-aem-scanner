package burp.scannercheck;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

import java.net.URL;
import java.util.List;

/**
 * Active scanner check based on  a base URL.
 * Actively scans a specific page which has been identified by the AEM fingerprinter.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface ActiveAemPageScan {

    /**
     * @param baseRequestResponse
     * @param aemPageUrl
     * @return
     */
    List<IScanIssue> scan(final IHttpRequestResponse baseRequestResponse, final URL aemPageUrl);
}
