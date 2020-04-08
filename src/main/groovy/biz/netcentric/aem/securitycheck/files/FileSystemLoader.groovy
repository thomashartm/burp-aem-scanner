package biz.netcentric.aem.securitycheck.files

import java.nio.file.*
import java.nio.file.attribute.BasicFileAttributes
import java.util.stream.Collectors

/**
 * Loads source files from the file system which can be a simple path outside or inside of a jar.
 */
class FileSystemLoader {

    List<Source> loadFiles(String path) {

        URL resource = this.getClass().getResource(path)
        if(resource != null){
            return loadFiles(resource, path)
        }

        Collections.emptyList()
    }

    List<Source> loadFiles(URL url, String location) {
        assert url != null

        URI uri = url.toURI()
        List<Source> sources = []
        FileSystem fileSystem
        Path myPath
        try {
            if (uri.getScheme().equals("jar")) {
                fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object> emptyMap())
                fileSystem.getRootDirectories().each { path ->
                }
                myPath = fileSystem.getPath(location)
            } else {
                myPath = Paths.get(uri.toString());
            }

            Files.walkFileTree(myPath, new FileVisitor<Path>() {

                @Override
                FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    return FileVisitResult.CONTINUE
                }

                @Override
                FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    InputStream is
                    try {
                        is = Files.newInputStream(file, StandardOpenOption.READ)
                        sources << new Source(content: is.text, location: file.toUri().toString())
                    } catch (Exception ex) {
                        ex.printStackTrace()
                    } finally {
                        if (is != null) is.close()
                    }

                    return FileVisitResult.CONTINUE
                }

                @Override
                FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                    return FileVisitResult.TERMINATE
                }

                @Override
                FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    return FileVisitResult.CONTINUE
                }
            })
        } finally {
            if (fileSystem != null) {
                fileSystem.close()
            }
        }

        sources
    }
}
