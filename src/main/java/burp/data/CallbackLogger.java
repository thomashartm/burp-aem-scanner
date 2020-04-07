package burp.data;


import biz.netcentric.aem.securitycheck.util.Logger;
import burp.IBurpExtenderCallbacks;

public class CallbackLogger implements Logger {

    private IBurpExtenderCallbacks callbacks;

    public CallbackLogger(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void log(String message) {
        this.callbacks.printOutput(message);
    }

    @Override
    public void log(String pattern, String... messages) {
        this.callbacks.printOutput(String.format(pattern, messages));
    }

    @Override
    public void log(Exception ex) {
        this.callbacks.printOutput(ex.toString());
    }

    @Override
    public void log(Exception ex, String message) {
        this.callbacks.printOutput(message + " " + ex.toString());
    }

    @Override
    public void error(String message) {
        this.callbacks.printError(message);
    }

    @Override
    public void error(String pattern, String... messages) {
        this.callbacks.printError(String.format(pattern, messages));
    }

    @Override
    public void error(Exception ex) {
        this.callbacks.printError( ex.toString());
    }

    @Override
    public void error(Exception ex, String message) {
        this.callbacks.printError(message + " " + ex.toString());
    }
}
