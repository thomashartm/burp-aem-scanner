package biz.netcentric.aem.securitycheck.files

import java.util.stream.Collectors

class FileSystemLoader {

    static final String PATTERN_FILE_RESOURCE_PATH = "%s/%s"

    List<Source> loadFiles(String path) {
        try (InputStream inputStream = getResourceAsStream(path)) {
            if (inputStream != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))
                return reader.lines()
                        .map(fileName -> String.format(PATTERN_FILE_RESOURCE_PATH, path, fileName))
                        .map(fullFileResourcePath -> loadFileContent(fullFileResourcePath))
                        .filter(optional -> optional.isPresent())
                        .map(spec -> spec.get())
                        .collect(Collectors.toList())
            } else {
                System.out.println("Path does not provide a readable stream" + path)
            }
        } catch (IOException e) {
            e.printStackTrace()
        }

        Collections.emptyList()
    }

    InputStream getResourceAsStream(String resource) {
        InputStream stream = getContextClassLoader().getResourceAsStream(resource)

        stream == null ? getClass().getResourceAsStream(resource) : stream
    }

    ClassLoader getContextClassLoader() {
        Thread.currentThread().getContextClassLoader()
    }

    Optional<Source> loadFileContent(String path) {
        try (InputStream inputStream = getResourceAsStream(path)) {
            ByteArrayOutputStream result = new ByteArrayOutputStream()
            byte[] buffer = new byte[1024]
            int length
            while ((length = inputStream.read(buffer)) != -1) {
                result.write(buffer, 0, length)
            }

            return Optional.of(new Source(content: result.toString(), location: path))
        } catch (IOException e) {
            e.printStackTrace()
        }

        Optional.empty()
    }
}
