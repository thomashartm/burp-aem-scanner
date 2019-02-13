package burp.actions.http;

import java.net.URL;

/**
 * Http method to simplify the crafting and execution of http calls
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public interface HttpMethod {

    /**
     * Init the stateful method object
     *
     * @param newUrlTarget
     */
    void init(URL newUrlTarget);

    /**
     * Send the request
     *
     * @return
     */
    ResponseHolder send();
}
