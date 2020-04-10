package burp.ui;

import biz.netcentric.aem.securitycheck.SecurityCheckService;
import burp.IHttpRequestResponse;
import burp.data.BurpContext;
import burp.data.BurpHelperDto;
import burp.http.BurpHttpClientProvider;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Constructor;
import java.util.concurrent.Callable;

/**
 * Adds the default get servlet checks to the menu. Instantiates a list of generic callables and triggers them via a threadpool.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class RunChecksActionListener implements ActionListener {

    private static final int NUMBER_OF_PARALLEL_SCANS = 1;

    private final BurpHelperDto helperDto;

    private final SecurityCheckService securityCheckService;

    private final AsyncCheckExecutor executor;

    /**
     * {@link Constructor} for a generic action listener
     *
     * @param helperDto The DTO for burp internal functionality
     */
    public RunChecksActionListener(final SecurityCheckService securityCheckService, final BurpHelperDto helperDto) {
        this.helperDto = helperDto;
        this.securityCheckService = securityCheckService;
        this.executor = new AsyncCheckExecutor(NUMBER_OF_PARALLEL_SCANS);
    }

    @Override
    public void actionPerformed(final ActionEvent event) {
        this.helperDto.getCallbacks().printOutput("GenericCheckActionListener triggered. " + event.toString());
        final IHttpRequestResponse[] messages = this.helperDto.getIContextMenuInvocation().getSelectedMessages();

        final BurpContext context = BurpContext.builder()
                .logger(this.helperDto.getLogger())
                .clientProvider(new BurpHttpClientProvider(this.helperDto, messages[0]))
                .build();

        this.executor.executeAsync(new SecurityCheckCallable(securityCheckService, context));
    }

    static class SecurityCheckCallable implements Callable {
        private SecurityCheckService securityCheckService;

        private BurpContext context;

        public SecurityCheckCallable(SecurityCheckService securityCheckService, BurpContext context) {
            this.securityCheckService = securityCheckService;
            this.context = context;
        }

        @Override
        public Object call() throws Exception {
            // TODO this is the entry point to trigger any subsequent action with the provided SecurityCheckService dependency
            securityCheckService.runSecurityChecks(context);
            return true;
        }
    }
}
