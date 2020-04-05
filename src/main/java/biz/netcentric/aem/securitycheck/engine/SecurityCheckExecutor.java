package biz.netcentric.aem.securitycheck.engine;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecurityCheckExecutor {

    private final int threadPoolSize;

    private ExecutorService executorService;

    public SecurityCheckExecutor(final int fixedThreadPoolSize) {
        this.threadPoolSize = fixedThreadPoolSize;

        // TODO make thread pool size configurable
        // TODO exec the future tasks returned by the callables e.g. to display results
        this.init();

    }

    public void stop() {
        if (!this.executorService.isTerminated()) {
            this.executorService.shutdownNow();
        }
    }

    public void init() {
        if (this.executorService == null || this.executorService.isTerminated()) {
            this.executorService = Executors.newFixedThreadPool(this.threadPoolSize);
        }
    }

    public void executeAsync(final Callable<CheckResult> callable) {
        if (!this.executorService.isTerminated()) {
            executorService.submit(callable);
        }
    }

}