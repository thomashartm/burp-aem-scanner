package biz.netcentric.aem.securitycheck.files;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

class FileSystemResourceLoaderTest {

    @Test
    void loadFiles() throws IOException {
        FileSystemResourceLoader resourceLoader = new FileSystemResourceLoader();
        List<SourceFile> resources = resourceLoader.loadFiles("/yamlloadertest");
        for (SourceFile resource : resources) {
            System.out.println(resource);
        }
    }
}