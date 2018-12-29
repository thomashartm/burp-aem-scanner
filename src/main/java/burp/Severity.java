package burp;

/**
 * Severity of a scan issue.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 12/2018
 */
public enum Severity {

    HIGH("High"),
    MEDIUM("Medium"),
    LOW("Low"),
    INFORMATION("Information");

    private final String value;

    Severity(final String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}
