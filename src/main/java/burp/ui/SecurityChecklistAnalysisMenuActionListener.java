package burp.ui;

import burp.*;
import burp.actions.accesscontrol.AnonymousWriteAccessCheckCallable;
import burp.actions.dispatcher.DispatcherPathCheckCallable;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Supposed to trigger the dispatcher related scanning issues
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class SecurityChecklistAnalysisMenuActionListener implements ActionListener {

    public static final String BASE_PATH = "/";

    private final IContextMenuInvocation invocation;

    private final BurpHelperDto helperDto;

    private BurpExtender extender;

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    public SecurityChecklistAnalysisMenuActionListener(final BurpHelperDto helperDto) {
        this.helperDto = helperDto;
        this.extender = helperDto.getExtender();
        this.callbacks = helperDto.getCallbacks();
        this.helpers = helperDto.getHelpers();
        this.invocation = helperDto.getiContextMenuInvocation();
    }

    @Override
    public void actionPerformed(final ActionEvent event) {
        this.callbacks.printOutput("AEMSecurityAnalysisMenuActionListener performed");

        final IHttpRequestResponse[] messages = this.invocation.getSelectedMessages();
        final Map<String, IHttpRequestResponse> baseMessages = deDublicateByProtocolHostPort(messages);

        final ExecutorService pool = Executors.newFixedThreadPool(10);

        // now we start crafting requests for our vulnerabilities
        for (final Map.Entry<String, IHttpRequestResponse> baseMessage : baseMessages.entrySet()) {
            pool.submit(new DispatcherPathCheckCallable(this.helperDto, baseMessage.getValue()));
            pool.submit(new AnonymousWriteAccessCheckCallable(this.helperDto, baseMessage.getValue()));
            this.callbacks.printOutput("Dispatcher checklist related callables submitted for execution");
        }
    }

    private Map<String, IHttpRequestResponse> deDublicateByProtocolHostPort(final IHttpRequestResponse[] messages) {
        final Map<String, IHttpRequestResponse> baseMessages = new HashMap<>();

        for (final IHttpRequestResponse message : messages) {
            final IHttpService httpService = message.getHttpService();
            try {
                final URL baseUrl = new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), BASE_PATH);
                this.callbacks.printOutput(baseUrl.toString());
                baseMessages.put(baseUrl.toString(), message);
            } catch (MalformedURLException e) {
                this.callbacks.printError("Url format not supported. " + e);
            }
        }

        return baseMessages;
    }
}

