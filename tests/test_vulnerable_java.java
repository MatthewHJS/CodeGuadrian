/**
 * This file contains intentional vulnerabilities for testing CodeGuardian.
 * DO NOT USE THIS CODE IN PRODUCTION!
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;

public class VulnerableJavaCode {
    
    // Hardcoded credentials (vulnerability)
    private static final String DB_USERNAME = "admin";
    private static final String DB_PASSWORD = "super_secret_password123";
    private static final String API_KEY = "1234567890abcdef";
    
    // Hardcoded IP address (vulnerability)
    private static final String SERVER_IP = "192.168.1.100";
    
    /**
     * Connect to a database with user input.
     * @param userInput User-provided input
     * @return Number of rows affected
     */
    public static int connectToDatabase(String userInput) {
        try {
            // SQL Injection vulnerability
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", DB_USERNAME, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            return stmt.executeUpdate(query); // Vulnerable to SQL injection
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return 0;
        }
    }
    
    /**
     * Run a system command.
     * @param command User-provided command
     */
    public static void runCommand(String command) {
        try {
            // Command injection vulnerability
            Runtime.getRuntime().exec("ls " + command); // Vulnerable to command injection
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    /**
     * Load a serialized object from a file.
     * @param filename Name of the file to load
     * @return The deserialized object
     */
    public static Object loadObject(String filename) {
        try {
            // Insecure deserialization vulnerability
            FileInputStream fis = new FileInputStream(filename);
            ObjectInputStream ois = new ObjectInputStream(fis);
            return ois.readObject(); // Vulnerable to deserialization attacks
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Generate a random token.
     * @return A random token
     */
    public static int generateToken() {
        // Insecure randomness
        Random random = new Random(); // Not cryptographically secure
        return random.nextInt(100000);
    }
    
    /**
     * Read a file with user input.
     * @param filename User-provided filename
     * @return The file content
     */
    public static String readFile(String filename) {
        try {
            // Path traversal vulnerability
            File file = new File("data/" + filename); // Vulnerable to path traversal
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            return new String(data, "UTF-8");
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Configure XML parser.
     * @return Configured DocumentBuilderFactory
     */
    public static DocumentBuilderFactory configureXMLParser() {
        // XXE vulnerability
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing secure processing configuration
        return factory; // Vulnerable to XXE attacks
    }
    
    /**
     * Initialize a cipher with a weak algorithm.
     * @return Configured Cipher
     */
    public static Cipher initializeCipher() {
        try {
            // Weak cryptographic algorithm
            return Cipher.getInstance("DES/ECB/PKCS5Padding"); // DES is weak, ECB mode is insecure
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Process an exception.
     * @param e The exception to process
     */
    public static void processException(Exception e) {
        // Catching generic Exception
        try {
            // Do something with the exception
            System.out.println(e.getMessage());
        } catch (Exception ex) {
            // Catching generic Exception is not recommended
            System.out.println("Error: " + ex.getMessage());
        }
    }
    
    /**
     * Main method.
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        System.out.println("Running vulnerable Java code...");
        
        // Call vulnerable functions
        connectToDatabase("user' OR '1'='1");
        runCommand("-la; cat /etc/passwd");
        
        try {
            loadObject("data.ser");
        } catch (Exception e) {
            processException(e);
        }
        
        int token = generateToken();
        System.out.println("Generated token: " + token);
        
        try {
            readFile("../../../etc/passwd");
        } catch (Exception e) {
            processException(e);
        }
        
        configureXMLParser();
        initializeCipher();
    }
} 