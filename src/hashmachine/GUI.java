package hashmachine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.util.ArrayList;

public class GUI
        implements ActionListener {
    private static final String TITLE = "Hash Machine (9.9.2017)";
    private static final String SRC_TEXT = "text";
    private static final String SRC_FILE = "file";
    private final JScrollPane scrollPane;
    private JComboBox<String> srcCombo;
    private JTextField textField;
    private JButton evalButton;
    private JTextField keyField;
    private JButton checkButton;

    private static final HashMethod[] METHODS;

    static {
        METHODS = new HashMethod[]{
//                new HashMethod("MD2 (128)", "MD2"),
//                new HashMethod("MD4 (128)", "MD4"),
                new HashMethod("MD5 (128)", "MD5"),
//                new HashMethod("RIPE (128)", "RIPEMD128"),
                new HashMethod("RIPE (160)", "RIPEMD160"),
//                new HashMethod("RIPE (256)", "RIPEMD256"),
//                new HashMethod("RIPE (320)", "RIPEMD320"),
                new HashMethod("SHA1 (160)", "SHA1"),
                new HashMethod("SHA2 (224)", "SHA224"),
                new HashMethod("SHA2 (256)", "SHA256"),
                new HashMethod("SHA2 (384)", "SHA384"),
                new HashMethod("SHA2 (512)", "SHA512"),
                new HashMethod("SHA3 (224)", "SHA3-224"),
                new HashMethod("SHA3 (256)", "SHA3-256"),
                new HashMethod("SHA3 (384)", "SHA3-384"),
                new HashMethod("SHA3 (512)", "SHA3-512"),
//                new HashMethod("SM3 (256)", "SM3"),
//                new HashMethod("Tiger (192)", "Tiger"),
//                new HashMethod("GOST3411 (256)", "GOST3411"),
//                new HashMethod("Whirlpool (512)", "Whirlpool"),
        };
    }

    private final JFrame frame;
    private JFileChooser fileChooser;
    private JTextField signField;

    public static void main(String[] args)
            throws IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        if (args.length == 0) {
            new GUI();
            return;
        }

        ArrayList<String> algoList = new ArrayList<>();
        for (String arg : args) {
            if (arg.startsWith("-")) {
                String algo = guessAlgo(arg.substring(1).toLowerCase());
                if (algo != null)
                    algoList.add(algo);
            } else {
                File file = new File(arg);
                for (String algo : algoList) {
                    String hash = eval(algo, file);
                    System.out.printf("%s: %s%n", algo, hash);
                }
                System.out.println();
            }
        }
    }

    private static String guessAlgo(String s) {
        if (s.equals("md2")) return "MD2";
        if (s.equals("md4")) return "MD4";
        if (s.equals("md5")) return "MD5";
        if (s.contains("ripe")) {
            if (s.contains("128")) return "RIPEMD128";
            if (s.contains("160")) return "RIPEMD160";
            if (s.contains("256")) return "RIPEMD256";
            if (s.contains("320")) return "RIPEMD320";
            return null;
        }
        if (s.contains("sha")) {
            if (s.contains("224")) return "SHA224";
            if (s.contains("256")) return "SHA256";
            if (s.contains("384")) return "SHA384";
            if (s.contains("512")) return "SHA512";
            return "SHA1";
        }
        if (s.contains("sha3")) {
            if (s.contains("224")) return "SHA3-224";
            if (s.contains("256")) return "SHA3-256";
            if (s.contains("384")) return "SHA3-384";
            if (s.contains("512")) return "SHA3-512";
            return null;
        }
        if (s.contains("whirlpool")) return "Whirlpool";
        return null;
    }

    private GUI() {
        frame = new JFrame(TITLE);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        Container container = frame.getContentPane();

        container.add(mkNorthPanel(), BorderLayout.NORTH);
        scrollPane = new JScrollPane(mkCentralPanel());
        container.add(scrollPane, BorderLayout.CENTER);

        frame.pack();
        frame.setVisible(true);
    }

    private Component mkNorthPanel() {
        JPanel box = new JPanel();
        GroupLayout layout = new GroupLayout(box);
        box.setLayout(layout);

        srcCombo = new JComboBox<>();
        srcCombo.addItem(SRC_TEXT);
        srcCombo.addItem(SRC_FILE);
        box.add(srcCombo);

        textField = new JTextField(40);
        textField.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (!SRC_FILE.equals(srcCombo.getSelectedItem()))
                    return;
                if (fileChooser == null)
                    fileChooser = new JFileChooser();
                int res = fileChooser.showOpenDialog(frame);
                if (res != JFileChooser.APPROVE_OPTION)
                    return;
                File selectedFile = fileChooser.getSelectedFile();
                if (selectedFile == null)
                    return;
                textField.setText(selectedFile.getAbsolutePath());
            }
        });
        box.add(textField);

        evalButton = new JButton("eval");
        evalButton.addActionListener(this);
        box.add(evalButton);

        JLabel keyLabel = new JLabel("key:");
        box.add(keyLabel);
        keyField = new JTextField(40);
        box.add(keyField);
        JComponent blank = new JLabel("");
        box.add(blank);

        signField = new JTextField();
        box.add(signField);

        checkButton = new JButton("check");
        checkButton.addActionListener(this);
        box.add(checkButton);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        GroupLayout.SequentialGroup groupC1_R1 =
                layout.createSequentialGroup()
                        .addComponent(srcCombo)
                        .addComponent(textField);
        GroupLayout.SequentialGroup groupC1_R2 =
                layout.createSequentialGroup()
                        .addComponent(keyLabel)
                        .addComponent(keyField);
        GroupLayout.ParallelGroup groupC1 =
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(groupC1_R1)
                        .addGroup(groupC1_R2)
                        .addComponent(signField);
        GroupLayout.ParallelGroup groupC2 =
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(evalButton)
                        .addComponent(blank)
                        .addComponent(checkButton);
        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(groupC1)
                        .addGroup(groupC2)
        );

        GroupLayout.ParallelGroup groupR1 =
                layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(srcCombo)
                        .addComponent(textField)
                        .addComponent(evalButton);
        GroupLayout.ParallelGroup groupR2 =
                layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(keyLabel)
                        .addComponent(keyField)
                        .addComponent(blank);
        GroupLayout.ParallelGroup groupR3 =
                layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(signField)
                        .addComponent(checkButton);
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(groupR1)
                        .addGroup(groupR2)
                        .addGroup(groupR3)
        );

        return box;
    }

    private JPanel mkCentralPanel() {
        LabelledItemPanel panel = new LabelledItemPanel();

        for (HashMethod method : METHODS) {
            method.checkBox = new JCheckBox();
            method.checkBox.setSelected(true);
            method.field = new JTextField(40);
            JPanel p1 = new JPanel();
            p1.add(method.checkBox);
            p1.add(method.field);
            panel.addItem(method.name, p1);
        }

        return panel;
    }

    @Override
    public void actionPerformed(ActionEvent event) {
        try {
            JComponent src = (JComponent) event.getSource();

            if (src == evalButton) {
                for (HashMethod method : METHODS)
                    method.field.setText("");
                String textString = textField.getText();
                if (textString == null || textString.length() == 0)
                    return;
                String keyString = keyField.getText();
                byte[] keyBytes = keyString.getBytes("UTF-8");

                if (SRC_TEXT.equals(srcCombo.getSelectedItem())) {
                    byte[] textBytes = textString.getBytes("UTF-8");
                    for (HashMethod method : METHODS) {
                        if (method.checkBox.isSelected()) {
                            if (keyBytes.length == 0)
                                method.field.setText(eval(method, textBytes));
                            else
                                method.field.setText(eval(method, textBytes, keyBytes));
                        }
                    }

                } else {
                    File file = new File(textString);
                    for (HashMethod method : METHODS) {
                        if (method.checkBox.isSelected()) {
                            if (keyBytes.length == 0)
                                method.field.setText(eval(method, file));
                            else
                                method.field.setText(eval(method, file, keyBytes));
                        }
                    }
                }

                scrollPane.revalidate();
            }

            if (src == checkButton) {
                String sign = adapt(signField.getText());
                if (sign.length() == 0)
                    return;
                for (HashMethod method : METHODS)
                    method.checkBox.setSelected(false);
                if (matches(sign))
                    signField.setBackground(Color.GREEN);
                else
                    signField.setBackground(Color.RED);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean matches(String sign) {
        for (HashMethod method : METHODS) {
            if (method.field.getText().equalsIgnoreCase(sign)) {
                method.checkBox.setSelected(true);
                return true;
            }
        }
        return false;
    }

    private String adapt(String text) {
        StringBuilder builder = new StringBuilder();
        for (char ch : text.toCharArray()) {
            if (isHex(ch))
                builder.append(ch);
        }
        return builder.toString();
    }

    @SuppressWarnings("RedundantIfStatement")
    private boolean isHex(char ch) {
        if (Character.isDigit(ch))
            return true;
        if (ch >= 'A' && ch <= 'F')
            return true;
        if (ch >= 'a' && ch <= 'f')
            return true;
        return false;
    }

    private String eval(HashMethod method, byte[] textBytes)
            throws NoSuchProviderException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(method.javaName, "BC");
            byte[] digest = messageDigest.digest(textBytes);
            return DatatypeConverter.printHexBinary(digest);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        }
    }

    private String eval(HashMethod method, byte[] textBytes, byte[] keyBytes)
            throws NoSuchProviderException {
        try {
            String hmacName = "HMAC-" + method.javaName;
            Mac mac = Mac.getInstance(hmacName, "BC");
            SecretKey secretKey = new SecretKeySpec(keyBytes, hmacName);
            mac.init(secretKey);
            mac.update(textBytes);
            byte[] hmac = mac.doFinal();
            return DatatypeConverter.printHexBinary(hmac);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        } catch (InvalidKeyException e) {
            return "Invalid key exception";
        }
    }

    private String eval(HashMethod method, File file)
            throws IOException, NoSuchProviderException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(method.javaName, "BC");
            byte[] bytes = new byte[1024];
            try (InputStream in = new FileInputStream(file)) {
                for (; ; ) {
                    int n = in.read(bytes);
                    if (n <= 0)
                        break;
                    messageDigest.update(bytes, 0, n);
                }
            }
            byte[] digest = messageDigest.digest();
            return DatatypeConverter.printHexBinary(digest);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        }
    }

    private String eval(HashMethod method, File file, byte[] keyBytes)
            throws IOException, NoSuchProviderException {
        try {
            String hmacName = "HMAC-" + method.javaName;
            Mac mac = Mac.getInstance(hmacName, "BC");
            SecretKey secretKey = new SecretKeySpec(keyBytes, hmacName);
            mac.init(secretKey);
            byte[] bytes = new byte[1024];
            try (InputStream in = new FileInputStream(file)) {
                for (; ; ) {
                    int n = in.read(bytes);
                    if (n <= 0)
                        break;
                    mac.update(bytes, 0, n);
                }
            }
            byte[] hmac = mac.doFinal();
            return DatatypeConverter.printHexBinary(hmac);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        } catch (InvalidKeyException e) {
            return "Invalid key exception";
        }
    }

    private static String eval(String method, File file)
            throws IOException, NoSuchProviderException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(method, "BC");
            byte[] bytes = new byte[1024];
            try (InputStream in = new FileInputStream(file)) {
                for (; ; ) {
                    int n = in.read(bytes);
                    if (n <= 0)
                        break;
                    messageDigest.update(bytes, 0, n);
                }
            }
            byte[] digest = messageDigest.digest();
            return DatatypeConverter.printHexBinary(digest);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        }
    }

    private static class HashMethod {
        final String name;
        final String javaName;

        JTextField field;
        JCheckBox checkBox;

        HashMethod(String name, String javaName) {
            this.name = name;
            this.javaName = javaName;
        }
    }
}
