package burp.ui;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AsyncCheckExecutor {

    private final int threadPoolSize;

    private ExecutorService executorService;

    public AsyncCheckExecutor(final int fixedThreadPoolSize) {
        this.threadPoolSize = fixedThreadPoolSize;
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

    public void executeAsync(final Callable<Boolean> callable) {
        if (!this.executorService.isTerminated()) {
            executorService.submit(callable);
        }
    }
}
