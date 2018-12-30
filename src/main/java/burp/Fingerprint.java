package burp;

import org.apache.commons.lang3.StringUtils;

import java.net.URL;

/**
 * Elements typically present inside of an AEM website. Indicating  presence of typical AEM components, DAM, clientlibs ora CRX repository structure.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public enum Fingerprint {

    JCR_CONTENT("jcr_content"),
    JCR_CONTENT2("jcr:content"),
    PARSYS("parsys"),
    CLIENTLIBS("/clientlibs"),
    ETC_CLIENTLIBS_PROXY_PATH("/etc.clientlibs"),
    CONTENT_DAM("/content/dam"),
    ETC_DESIGNS("/etc/designs"),
    ETC_CLIENTLIBS("/etc/clientlibs");

    private String value;

    Fingerprint(final String value) {
        this.value = value;
    }

    /**
     * Checks wether the {@link Fingerprint}'s value is present in the provided URL
     *
     * @param url Url
     * @return True if it is present in the path
     */
    public boolean isPresentInUrl(final URL url) {
        return StringUtils.contains(url.getPath(), this.value);
    }

    /**
     * Provides the fingerprint value which is typically a token present somewhere in the url, or a link or the actual content.
     *
     * @return
     */
    public String getValue() {
        return value;
    }
}
