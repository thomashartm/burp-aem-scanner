package burp.util;

/**
 * Provides comparison functionality to the implementer
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public interface WithComparator {

    /**
     * Upper and lower bound status code checks
     *
     * @param value      Current value
     * @param lowerBound lower bound
     * @param upperBound upper bound
     * @return True if within.
     */
    default boolean isInRange(short value, int lowerBound, int upperBound) {
        final Integer intval = Integer.valueOf(value);
        return lowerBound <= intval && intval <= upperBound;
    }
}
