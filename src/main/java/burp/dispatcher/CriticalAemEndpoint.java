package burp.dispatcher;

import burp.Severity;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Critical aem endpoint such as CRX,
 * system/console and other administrative resources which either expose ot much information or even allow administrative access.
 * <p>
 * Each endpoint is rated with a severity and comes with some descriptive information.
 * List is based on https://helpx.adobe.com/experience-manager/dispatcher/using/dispatcher-configuration.html#TestingDispatcherSecurity
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public enum CriticalAemEndpoint {

    ADMIN("/admin", Severity.HIGH, "Critical AEM Resource", ""),
    SYSTEM_CONSOLE("/system/console", Severity.HIGH, "System Console accessible",
            "The system console is an administrative feature allowing full control over the application."),
    SYSTEM_CONSOLE_HTML("/system/console.html", Severity.HIGH, "System Console accessible",
            "The system console is an administrative feature allowing full control over the application."),
    DAV_EX("/dav/crx.default", Severity.HIGH, "WebDav Access is enabled",
            "Webdav access to the repository is still enabled and accessible from the outside. It is directly exploitable."),
    CRX1("/crx", Severity.HIGH, "CRX DE accessible",
            "CRX DE is an DE util which allows access to critical backend configurations. It is directly exploitable."),
    CRX_DE("/crx/de", Severity.HIGH, "CRX DE accessible",
            "CRX explorer is an administrative util which allows access to critical backend configurations. It is directly exploitable."),
    CRX_DE_INDEX("/crx/de/index.jsp", Severity.HIGH, "CRX DE accessible",
            "CRX explorer is an administrative util which allows access to critical backend configurations. It is directly exploitable."),
    CRX_EXPLORER("/crx/explorer", Severity.HIGH, "CRX Explorer accessible",
            "CRX explorer is an administrative util which allows access to critical backend configurations. It is directly exploitable."),
    CRX_EXPLORER_JSP("/crx/explorer/index.jsp", Severity.HIGH, "CRX Explorer accessible",
            "CRX explorer is an administrative util which allows access to critical backend configurations. It is directly exploitable."),
    CRX_LOGS("/bin/crxde/logs", Severity.HIGH, "Critical AEM Resource",
            "An administrative util which allows access to server side logfiles."),
    VERSION_STORE("/jcr:system/jcr:versionStorage.json", Severity.HIGH, "Critical AEM Resource", ""),
    VERSION_STORE_1("/_jcr_system/_jcr_versionStorage.json", Severity.HIGH, "Critical AEM Resource", ""),
    SITEADMIN("/libs/wcm/core/content/siteadmin.html", Severity.HIGH, "Critical AEM Resource",
            "The siteadmin is the main backend for content authors and editors. It should not be accessible on publishing instances."),
    COLLAB_ADMIN("/libs/collab/core/content/admin.html", Severity.HIGH, "Critical AEM Resource",
            "The collabadmin is the main backend for the collaboration functionality. It should not be accessible on publishing instances."),
    DUMPLIBS("/libs/cq/ui/content/dumplibs.html", Severity.HIGH, "Critical AEM Resource", ""),
    LINKCHECKER("/var/linkchecker.html", Severity.HIGH, "Critical AEM Resource", ""),
    LINKCHECKER1("/etc/linkchecker.html", Severity.HIGH, "Critical AEM Resource", ""),
    PROFILE_JSON("/home/users/a/admin/profile.json", Severity.HIGH, "Critical AEM Resource", ""),
    PROFILE_XML("/home/users/a/admin/profile.xml", Severity.HIGH, "Critical AEM Resource", ""),
    LOGIN("/libs/cq/core/content/login.json", Severity.HIGH, "Critical AEM Resource",
            "Login interface for the AEM backend. Should not be accessible on publishing instances."),
    FOUNDATION_TEXT_BYPASS("/content/../libs/foundation/components/text/text.jsp", Severity.HIGH, "Dispatcher Filter Rule Bypass",
            "This issue is a filter rule bypass indicating that filter rules can be bypassed by using special characters."),
    FOUNDATION_TEXT_BYPASS1("/content/.{.}/libs/foundation/components/text/text.jsp", Severity.HIGH,
            "Dispatcher Filter Rule Bypass",
            "This issue is a filter rule bypass indicating that filter rules can be bypassed by using special characters."),
    WEBCONSOLE_BUNDLE_ACCESS(
            "/apps/sling/config/org.apache.felix.webconsole.internal.servlet.OsgiManager.config/jcr%3acontent/jcr%3adata",
            Severity.HIGH,
            "Sensitive Configuration Leakage",
            "This issue indicates that osgi system configurations deployed to the /apps directory can be directly accessed. This configurations may contain sensitive data."),
    WORKFLOW_PARTICIPANTS("/libs/foundation/components/primary/cq/workflow/components/participants/json.GET.servlet",
            Severity.HIGH,
            "Sensitive User Data Leakage",
            "This endpoint leaks the participants taking part in backend workflows. The information may contain user IDs."),
    CONTENT_INFO("/content.pages.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_INFO_LANG("/content.languages.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_INFO_BLUEPRINT("/content.blueprint.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_METADATA_1("/content.-1.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_METADATA_10("/content.10.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_METADATA_INFIONITY("/content.infinity.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_METADATA_TIDY("/content.tidy.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_METADATA_TIDY_BLUBBER("/content.tidy.-1.blubber.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_METADATA_TIDY_100("/content/dam.tidy.-100.json", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_DEFAULT_CONTENT_SITEMAP("/content/content/geometrixx.sitemap.txt", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    CONTENT_DEFAULT_CONTENT_SITEMAP2("/content/geometrixx.sitemap.txt", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    ETC("/etc.xml", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    FEED("/content.feed.xml", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    RSS("/content.rss.xml", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs."),
    FEED_HTML("/content.feed.html", Severity.MEDIUM, "Sensitive User Data Leakage",
            "The information may be used to recon the internal information aerchitecture and to disclose sensitive metadata such as user IDs.");

    String path;

    String name;

    String description;

    Severity severity;

    CriticalAemEndpoint(final String path, final Severity severity, final String name, final String description) {
        this.path = path;
        this.name = name;
        this.description = description;
        this.severity = severity;
    }

    /**
     * The current path of the critical endpoint
     *
     * @return String path
     */
    public String getPath() {
        return path;
    }

    /**
     * Uses the provides parameters to create a ready to use URL.
     *
     * @param scheme Scheme to prefix the url. Typically it is either https or http but it is not enforced.
     * @param host   hostname to use for the URL
     * @param port   Port to consider when building the url
     * @return A URL
     * @throws MalformedURLException
     */
    public URL toUrl(final String scheme, final String host, final int port) throws MalformedURLException {
        return new URL(scheme, host, port, path);
    }

    /**
     * Uses the provides parameters to create a ready to use URL.
     *
     * @param scheme Scheme is either https or http
     * @param host   hostname to use for the URL
     * @return A URL
     * @throws MalformedURLException
     */
    public URL toUrl(final String scheme, final String host) throws MalformedURLException {
        return new URL(scheme, host, path);
    }

    /**
     * Informative name of the critical resource
     *
     * @return String of the name
     */
    public String getName() {
        return name;
    }

    /**
     * Description indicating the actual problem.
     *
     * @return Descriptive information as a String
     */
    public String getDescription() {
        return description;
    }

    /**
     * Severity indicates the impact of the detected issue.
     *
     * @return Severity level
     */
    public Severity getSeverity() {
        return severity;
    }
}
