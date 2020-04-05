package biz.netcentric.aem.securitycheck.model;

/**
 * Confidence of a result issue
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public enum Confidence {

    CERTAIN("Certain"),
    FIRM("Firm"),
    TENATIVE("Tentative");

    private final String value;

    /**
     * Constructor
     *
     * @param value
     */
    Confidence(final String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}