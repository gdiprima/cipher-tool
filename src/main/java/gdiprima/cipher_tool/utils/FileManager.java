package gdiprima.cipher_tool.utils;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class FileManager {

	public static byte[] readFileContent(String path) throws IOException {
		return Files.readAllBytes(getFilePath(path));
	}
	
	public static String readFileAsString(String path) throws IOException {
		return String.join("", Files.readAllLines(getFilePath(path)));
	}
	
	public static void writeFileContent(String path, byte[] content) throws IOException {
		Files.write(getFilePath(path), content, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
	}
	
	public static Path getFilePath(String path) {
		return Paths.get(URI.create(path));
	}
}
