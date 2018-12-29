package burp;

import java.net.URL;
import java.util.Objects;

/**
 * A generic {@link ScanIssue implementation}
 */
public class ScanIssue implements IScanIssue, Comparable<ScanIssue> {

    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;
    private final String name;
    private final String detail;
    private final String severity;
    private final String confidence;

    private ScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity,
            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public int compareTo(ScanIssue o) {
        return getIssueDetail().compareTo(o.getIssueDetail());
    }

    @Override
    public int hashCode() {
        int nameCode = name.hashCode();
        int descCode = (detail == null) ? 0 : detail.hashCode();
        return 31 * nameCode + descCode;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ScanIssue other = (ScanIssue) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.detail, other.detail)) {
            return false;
        }
        return true;
    }

    public static final class ScanIssueBuilder {
        private IHttpRequestResponse baseRequestResponse;
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        private String name;
        private String detail;
        private String severity;
        private String confidence;
        private IExtensionHelpers helpers;

        private ScanIssueBuilder() {
        }

        public static ScanIssueBuilder aScanIssue() {
            return new ScanIssueBuilder();
        }

        public ScanIssueBuilder withHttpService(IHttpService httpService) {
            this.httpService = httpService;
            return this;
        }

        public ScanIssueBuilder IExtensionHelpers(IExtensionHelpers helpers) {
            this.helpers = helpers;
            return this;
        }

        public ScanIssueBuilder withIHttpRequestResponse(IHttpRequestResponse baseRequestResponse) {
            this.baseRequestResponse = baseRequestResponse;
            return this;
        }

        public ScanIssueBuilder withUrl(URL url) {
            this.url = url;
            return this;
        }

        public ScanIssueBuilder withHttpMessages(IHttpRequestResponse[] httpMessages) {
            this.httpMessages = httpMessages;
            return this;
        }

        public ScanIssueBuilder withName(String name) {
            this.name = name;
            return this;
        }

        public ScanIssueBuilder withDetail(String detail) {
            this.detail = detail;
            return this;
        }

        public ScanIssueBuilder withSeverity(final Severity severity) {
            this.severity = severity.getValue();
            return this;
        }

        public ScanIssueBuilder withSeverityHigh() {
            this.severity = "High";
            return this;
        }

        public ScanIssueBuilder withSeverityMedium() {
            this.severity = "Medium";
            return this;
        }

        public ScanIssueBuilder withSeverityLow() {
            this.severity = "Low";
            return this;
        }

        public ScanIssueBuilder withSeverityInformation() {
            this.severity = "Information";
            return this;
        }

        public ScanIssueBuilder withSeverityFalsePositive() {
            this.severity = "False positive";
            return this;
        }

        public ScanIssueBuilder withCertainConfidence() {
            this.confidence = "Certain";
            return this;
        }

        public ScanIssueBuilder withFirmConfidence() {
            this.confidence = "Firm";
            return this;
        }

        public ScanIssueBuilder withTenativeConfidence() {
            this.confidence = "Tentative";
            return this;
        }

        public ScanIssueBuilder fromExisting(IScanIssue existing) {
            this.httpService = existing.getHttpService();
            this.url = existing.getUrl();
            this.httpMessages = existing.getHttpMessages();
            this.name = existing.getIssueName();
            this.detail = existing.getIssueDetail();
            this.severity = existing.getSeverity();
            return this;
        }

        public ScanIssue build() {
            if (this.httpService == null && this.baseRequestResponse != null) {
                this.httpService = baseRequestResponse.getHttpService();
            }

            if (this.url == null && this.helpers != null) {
                this.url = helpers.analyzeRequest(baseRequestResponse).getUrl();
            }

            return new ScanIssue(httpService, url, httpMessages, name, detail, severity, confidence);
        }
    }
}