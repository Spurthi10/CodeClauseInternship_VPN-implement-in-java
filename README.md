# CodeClauseInternship_VPN-implement-in-java
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class VPNClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static String secretKey;

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("Connected to the server.");

        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        PrintWriter writer = new PrintWriter(outputStream, true);

        // Key exchange
        secretKey = reader.readLine();
        System.out.println("Received secret key from server.");

        BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
        String message;
        while (true) {
            System.out.print("Enter message: ");
            message = consoleReader.readLine();
            String encryptedMessage = encrypt(message, secretKey);
            writer.println(encryptedMessage);

            String response = reader.readLine();
            String decryptedResponse = decrypt(response, secretKey);
            System.out.println("Server response: " + decryptedResponse);
        }
    }

    private static String encrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = Base64.getDecoder().decode(data);
        return new String(cipher.doFinal(decrypted));
    }
}
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class VPNClientGUI extends Application {
    private VPNClient vpnClient;

    @Override
    public void start(Stage primaryStage) {
        vpnClient = new VPNClient();
        vpnClient.connect();

        Label label = new Label("Enter message:");
        TextField textField = new TextField();
        Button sendButton = new Button("Send");

        sendButton.setOnAction(e -> {
            String message = textField.getText();
            vpnClient.sendMessage(message);
        });

        VBox vbox = new VBox(label, textField, sendButton);
        Scene scene = new Scene(vbox, 300, 200);

        primaryStage.setScene(scene);
        primaryStage.setTitle("VPN Client");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class VPNServer {
    private static final int PORT = 12345;
    private static final String SECRET_KEY = "mySuperSecretKey"; // Symmetric key for simplicity

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server started. Waiting for clients...");
        
        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");
            new Thread(new ClientHandler(socket)).start();
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket socket;
        
        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                InputStream inputStream = socket.getInputStream();
                OutputStream outputStream = socket.getOutputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter writer = new PrintWriter(outputStream, true);

                // Key exchange
                writer.println(SECRET_KEY);
                
                String message;
                while ((message = reader.readLine()) != null) {
                    String decryptedMessage = decrypt(message, SECRET_KEY);
                    System.out.println("Received: " + decryptedMessage);
                    String response = "Echo: " + decryptedMessage;
                    writer.println(encrypt(response, SECRET_KEY));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static String encrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = Base64.getDecoder().decode(data);
        return new String(cipher.doFinal(decrypted));
    }
}
