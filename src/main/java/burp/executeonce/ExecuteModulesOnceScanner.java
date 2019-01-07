package burp.executeonce;

import burp.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Executes a list of registered scanning modules exactly once.
 * It avoids to use the doActiveScan method, because this method is called for each any every baseRequestResponse.
 * Instead the scan modules are executed only once per scan activation by misusing getInsertionPoints
 * <p>
 * The reason to misuse the getInsertionPoints, is right now the API does not allow to limit the scan executions:
 * https://support.portswigger.net/customer/en/portal/questions/16776337-confusion-on-insertionpoints-active-scan-module?new=16776337
 * <p>
 * So we go for the same way as the UploadScanner extension and
 * misuse the getInsertionPoints method which is only called once per scan by coincidence
 * See https://github.com/PortSwigger/upload-scanner/blob/master/UploadScanner.py
 */
public class ExecuteModulesOnceScanner implements ConsolidatingScanner, IScannerInsertionPointProvider {

    private final IBurpExtenderCallbacks callbacks;

    private final IExtensionHelpers helpers;

    private ConcurrentHashMap<String, Long> history = new ConcurrentHashMap<>();

    /**
     * Constructor
     *
     * @param callbacks IBurpExtenderCallbacks
     */
    public ExecuteModulesOnceScanner(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse,
            IScannerInsertionPoint iScannerInsertionPoint) {
        return Collections.emptyList();
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseHttpRequestResponse) {
        final String executionKey = createKey(baseHttpRequestResponse.getHttpService());
        final Long key = history.getOrDefault(executionKey, 0L);
        final long now = Calendar.getInstance().getTimeInMillis();

        if(key == 0 || key < now - 36000000) {
            this.callbacks.printOutput("ExecuteModulesOnceScanner " + baseHttpRequestResponse.toString());
            this.callbacks.printOutput(
                    "" + this.helpers.analyzeRequest(baseHttpRequestResponse.getHttpService(), baseHttpRequestResponse.getRequest())
                            .getUrl());
            // delegate modules as the active scan process is happening in here
            final List<ScannerModule> scannerModules = initScannerModules();

            /**
             * TODO Refactor Burp API limitation.
             * - Is there any other way to simply say "each active scanned HTTP requested once per scan"?
             */
            scannerModules.stream()
                    .map(module -> module.scan(baseHttpRequestResponse))
                    .filter(results -> !results.isEmpty())
                    .flatMap(Collection::stream)
                    .filter(scanIssue -> scanIssue != null)
                    .forEach(scanIssue -> this.callbacks.addScanIssue(scanIssue));

            this.history.put(executionKey, now);
        }
        return Collections.emptyList();
    }

    private String createKey(final IHttpService httpService){
        return httpService.getProtocol() + httpService.getHost() + httpService.getPort();
    }

    private List<ScannerModule> initScannerModules() {
        final List<ScannerModule> scannerModules = new ArrayList<>();
        scannerModules.add(new DispatcherPathModule(this.callbacks));
        scannerModules.add(new AnonymousWriteModule(this.callbacks));
        return scannerModules;
    }

}
