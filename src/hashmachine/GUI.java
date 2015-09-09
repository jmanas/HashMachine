package hashmachine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.*;
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

public class GUI
        implements ActionListener {
    private static final String TITLE = "Hash Machine (8.6.2015)";
    public static final String SRC_TEXT = "text";
    public static final String SRC_FILE = "file";
    private final JScrollPane scrollPane;
    private JComboBox<String> srcCombo;
    private JTextField textField;
    private JButton evalButton;
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

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new GUI();
    }

    GUI() {
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
//        SpringLayout layout = new SpringLayout();
//        JPanel box= new JPanel(layout);
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
                if (!srcCombo.getSelectedItem().equals(SRC_FILE))
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

        signField = new JTextField();
        box.add(signField);

        checkButton = new JButton("check");
        checkButton.addActionListener(this);
        box.add(checkButton);

/*
        String N = SpringLayout.NORTH;
        String S = SpringLayout.SOUTH;
        String E = SpringLayout.EAST;
        String W = SpringLayout.WEST;
        String VC = SpringLayout.VERTICAL_CENTER;

        layout.putConstraint(W, srcCombo, 5, W, box);
        layout.putConstraint(N, srcCombo, 5, N, box);

        layout.putConstraint(W, textField, 5, E, srcCombo);
        layout.putConstraint(VC, textField, 0, VC, srcCombo);

        layout.putConstraint(W, evalButton, 5, E, textField);
        layout.putConstraint(VC, evalButton, 0, VC, textField);

        layout.putConstraint(E, box, 5, E, evalButton);

        layout.putConstraint(W, signField, 5, W, box);
        layout.putConstraint(N, signField, 5, S, textField);
        layout.putConstraint(E, signField, 0, E, textField);

        layout.putConstraint(W, checkButton, 0, W, evalButton);
        layout.putConstraint(VC, checkButton, 0, VC, signField);
        layout.putConstraint(E, checkButton, 0, E, evalButton);

        layout.putConstraint(S, box, 5, S, signField);

        layout.putConstraint(N, checkButton, 0, N, signField);
*/

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        GroupLayout.SequentialGroup groupC1_R1 =
                layout.createSequentialGroup()
                        .addComponent(srcCombo)
                        .addComponent(textField);
        GroupLayout.ParallelGroup groupC1 =
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(groupC1_R1)
                        .addComponent(signField);
        GroupLayout.ParallelGroup groupC2 =
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(evalButton)
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
                        .addComponent(signField)
                        .addComponent(checkButton);
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(groupR1)
                        .addGroup(groupR2)
        );

        return box;
    }

    private JPanel mkCentralPanel() {
        LabelledItemPanel panel = new LabelledItemPanel();

        for (HashMethod method : METHODS) {
            JTextField textField = new JTextField(40);
            method.field = textField;
            panel.addItem(method.name, textField);
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
                String text = textField.getText();
                if (text == null || text.length() == 0)
                    return;
                if (srcCombo.getSelectedItem().equals(SRC_TEXT)) {
                    byte[] bytes = text.getBytes("UTF-8");
                    for (HashMethod method : METHODS)
                        method.field.setText(eval(method, bytes));

                } else {
                    File file = new File(text);
                    for (HashMethod method : METHODS)
                        method.field.setText(eval(method, file));
                }

                scrollPane.revalidate();
            }

            if (src == checkButton) {
                String sign = adapt(signField.getText());
                if (sign.length() == 0)
                    return;
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
            if (method.field.getText().equalsIgnoreCase(sign))
                return true;
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

    private boolean isHex(char ch) {
        if (Character.isDigit(ch))
            return true;
        if (ch >= 'A' && ch <= 'F')
            return true;
        if (ch >= 'a' && ch <= 'f')
            return true;
        return false;
    }

    private String eval(HashMethod method, byte[] bytes)
            throws NoSuchProviderException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(method.javaName, "BC");
            byte[] digest = messageDigest.digest(bytes);
            return Hex.toHexString(digest);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        }
    }

    private String eval(HashMethod method, File file)
            throws IOException, NoSuchProviderException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(method.javaName, "BC");
            byte[] bytes = new byte[1024];
            InputStream in = new FileInputStream(file);
            for (; ; ) {
                int n = in.read(bytes);
                if (n <= 0)
                    break;
                messageDigest.update(bytes, 0, n);
            }
            byte[] digest = messageDigest.digest();
            return Hex.toHexString(digest);
        } catch (NoSuchAlgorithmException e) {
            return "No Such Algorithm";
        }
    }

    private static class HashMethod {
        final String name;
        final String javaName;

        JTextField field;

        HashMethod(String name, String javaName) {
            this.name = name;
            this.javaName = javaName;
        }
    }
}
