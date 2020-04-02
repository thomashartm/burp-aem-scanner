package biz.netcentric.aem.securitycheck.files;

import java.io.*;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class FileSystemResourceLoader {

    private static final String PATTERN_FILE_RESOURCE_PATH = "%s/%s";

    public List<SourceFile> loadFiles(String path) {
        try (InputStream inputStream = getResourceAsStream(path)) {
            if (inputStream != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                return reader.lines()
                        .map(fileName -> String.format(PATTERN_FILE_RESOURCE_PATH, path, fileName))
                        .map(fullFileResourcePath -> loadFileContent(fullFileResourcePath))
                        .filter(spec -> !spec.isEmpty())
                        .collect(Collectors.toList());
            } else {
                System.out.println("Path does not provide a readable stream" + path);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Collections.emptyList();
    }

    private InputStream getResourceAsStream(String resource) {
        final InputStream in
                = getContextClassLoader().getResourceAsStream(resource);

        return in == null ? getClass().getResourceAsStream(resource) : in;
    }

    private ClassLoader getContextClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }

    private SourceFile loadFileContent(String path) {
        try (InputStream inputStream = getResourceAsStream(path)){
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }
            return new SourceFile(result.toString(),path);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return SourceFile.createEmpty();
    }
}