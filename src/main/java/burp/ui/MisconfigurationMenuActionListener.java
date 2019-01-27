package burp.ui;

import burp.BurpHelperDto;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.actions.misconfiguration.DebugFilterActiveCheckCallable;
import burp.actions.misconfiguration.MetaDataLeakageCheckCallable;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Executes misconfiguration checks
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class MisconfigurationMenuActionListener implements ActionListener {

    private final BurpHelperDto helperDto;

    /**
     * @param helperDto
     */
    public MisconfigurationMenuActionListener(final BurpHelperDto helperDto) {
        this.helperDto = helperDto;
    }

    @Override
    public void actionPerformed(final ActionEvent event) {
        this.helperDto.getCallbacks().printOutput("AEMSecurityAnalysisMenuActionListener performed");

        final IHttpRequestResponse[] messages = this.helperDto.getiContextMenuInvocation().getSelectedMessages();

        final ExecutorService pool = Executors.newFixedThreadPool(10);

        // now we start crafting requests for our vulnerabilities
        for (final  IHttpRequestResponse baseMessage : messages) {
            pool.submit(new DebugFilterActiveCheckCallable(this.helperDto, baseMessage));
            pool.submit(new MetaDataLeakageCheckCallable(this.helperDto, baseMessage));
            this.helperDto.getCallbacks().printOutput("Misconfiguration related callables submitted for execution");
        }
    }
}