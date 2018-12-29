package burp.dispatcher;

import burp.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Checks wether the website is vulnerable to content grabbing via sling default selectors.
 * These selector will provide alternate renditions of the currently requested page and may
 * lead to the disclosure of confidential metainformation e.g. user name via the cq:lastModified property.
 * The following selector.extension combinations can be considered critical.
 * <p>
 * .infinity.json, .tidy.json, .sysview.xml, .docview.json, .docview.xml, .-1.json, .1.json, .2.json, .query.json, .xml
 * The list is based on https://helpx.adobe.com/experience-manager/dispatcher/using/security-checklist.html#RestrictAccess
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public class ContentGrabbingScanListener implements IScannerCheck, IScannerListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static final String[] AEM_FINGERPRINTING_TOKENS = new String[]{
            "jcr_content/","/etc.clientlibs","/etc/designs",
    };

    public ContentGrabbingScanListener(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }


    @Override
    public void newScanIssue(IScanIssue iScanIssue) {

    }

    @Override
    public List<IScanIssue> doPassiveScan(final IHttpRequestResponse iHttpRequestResponse) {
        IResponseInfo response = this.helpers.analyzeResponseKeywords(iHttpRequestResponse.getResponse());
        response.
        return null;
    }

    @Override public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {

        this.callbacks.getSiteMap()
        return null;
    }

    @Override public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }
}
