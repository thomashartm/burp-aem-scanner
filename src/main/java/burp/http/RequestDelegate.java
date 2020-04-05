package burp.http;

import java.net.URL;

/**
 * Http method to simplify the crafting and execution of http calls.
 * Allows pre initialization as some messages may need some postprocessing before actually sending them.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public interface RequestDelegate {

    /**
     * Init the stateful method object
     *
     * @param url
     */
    void init(URL url, String... headers);

    /**
     * Adds a request parameter
     *
     * @param name
     * @param value
     */
    void addRequestParameter(final String name, final String value);

    /**
     * Adds a parameter to the body of the message
     *
     * @param name
     * @param value
     */
    void addBodyParameter(final String name, final String value);

    /**
     * Send the request but requires initialization before.
     *
     * @return
     */
    ResponseEntity send();

    /**
     * Takes care of the initialization and directly sends the request to the new target Url
     *
     * @param url
     * @return
     */
    ResponseEntity send(URL url);
}
