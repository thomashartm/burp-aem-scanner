package burp;

/**
 * Status code evaluations and checks.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface WithStatusCode {

    default boolean isInRange(short value, int lowerBound, int upperBound) {
        final Integer intval = Integer.valueOf(value);
        return lowerBound <= intval && intval <= upperBound;
    }
}
