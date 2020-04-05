package burp.ui;

import biz.netcentric.aem.securitycheck.SecurityCheckService;
import burp.IHttpRequestResponse;
import burp.data.BurpHelperDto;
import burp.http.BurpHttpClient;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Constructor;

/**
 * Adds the default get servlet checks to the menu. Instantiates a list of generic callables and triggers them via a threadpool.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class GenericCheckActionListener implements ActionListener {

    private final BurpHelperDto helperDto;

    private final SecurityCheckService securityCheckService;

    /**
     * {@link Constructor} for a generic action listener
     *
     * @param helperDto The DTO for burp internal functionality
     */
    public GenericCheckActionListener(final SecurityCheckService securityCheckService, final BurpHelperDto helperDto) {
        this.helperDto = helperDto;
        this.securityCheckService = securityCheckService;
    }

    @Override
    public void actionPerformed(final ActionEvent event) {
        this.helperDto.getCallbacks().printOutput("GenericCheckActionListener triggered. " + event.toString());
        final IHttpRequestResponse[] messages = this.helperDto.getIContextMenuInvocation().getSelectedMessages();

        final BurpHttpClient httpClient = new BurpHttpClient(this.helperDto, messages[0]);

        securityCheckService.runSecurityChecks(httpClient);
        // now we start crafting requests for our vulnerabilities
        // TODO this is the entry point to trigger any subsequent action with the provided SecurityCheckService dependency
    }
}
