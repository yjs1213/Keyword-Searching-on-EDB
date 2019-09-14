/*
  정보보호학과 14054027 유지상

  Module/Fileio.java

  파일 입출력을 위한 Class입니다. NIO 기반으로 구현하였습니다.


*/
package Module;

import CRYPT.AES;
import CRYPT.CTR;
import CRYPT.SHA1;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Vector;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.DataOutputStream;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Fileio {
    private String hakbun = "";
    private String password = "";
    private String des = "";
    private String data = "";
    private String ck = "";
    private DataOutputStream output;
    private Vector<String> textvector = new Vector<String>();
    private Vector<String> cipher = new Vector<String>();
    private Vector<String> kword = new Vector<String>();
    sqlcon mysql = new sqlcon();
    CTR ctr = new CTR();
    SHA1 sha1 = new SHA1();
    AES aes = new AES();

    public Fileio(String destination){
        des = destination;
        mysql.connect();
    }
    public void loadPlainTxt() throws IOException{ // 평문을 읽음

        for(int i = 0; i <10; i++){
            Path path = Paths.get(des+"f"+i+".txt");

            FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.READ);
            ByteBuffer byteBuffer = ByteBuffer.allocate(100);
            Charset charset = Charset.defaultCharset();

            int byteCount;

            while(true){
                 byteCount = fileChannel.read(byteBuffer);
                 if(byteCount == -1) break;
                 byteBuffer.flip();
                 data += charset.decode(byteBuffer).toString();
                 byteBuffer.clear();
            }

            fileChannel.close();
            System.out.println("f"+i+".txt 파일을 읽었습니다.");
            textvector.add((String)data); // vector에 한개씩 넣음
            data = "";
        }
    }
    public void loadKeyword() throws IOException{ // keyword 파일을 읽음

        Path path = Paths.get(des+"kword.txt");

        FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.READ);
        ByteBuffer byteBuffer = ByteBuffer.allocate(100);
        Charset charset = Charset.defaultCharset();

        int byteCount;

        while(true){
             byteCount = fileChannel.read(byteBuffer);
             if(byteCount == -1) break;
             byteBuffer.flip();
             data += charset.decode(byteBuffer).toString();
             byteBuffer.clear();
        }

        fileChannel.close();
        System.out.println("kword.txt 파일을 읽었습니다.");

        StringTokenizer list = new StringTokenizer(data);
        while(list.hasMoreTokens()){
            kword.add(list.nextToken("|")); // 토큰으로 각각의 키워드 구분하여 vector에 넣음
        }

        for(int i = 0; i < kword.size(); i++){
            System.out.println(kword.elementAt(i));
        }
        data = "";
    }
    public void saveCipTxt(String sn,String pass,DataOutputStream out) throws IOException{ // vector에 저장되어있는 평문을 암호화해서 저장
        String key = "";
        String tmp = "";
        output = out; // 이 함수를 설정자로 사용합니다. 학번과 비밀번호, DataOutputStream을 설정합니다.
        password = pass;
        hakbun = sn;

        key = sha1.SHA1forAES(password);

        for(int i = 0; i < 10; i++){
            tmp = ctr.CTREnc((String)textvector.elementAt(i), key);
            cipher.add(tmp);
            System.out.println("f"+i+".txt 암호화를 완료했습니다.");
        }

        for(int  i = 0; i < 10; i++){
            Path path = Paths.get(des+"c"+i+".txt");
            Files.createDirectories(path.getParent());

            FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

            Charset charset = Charset.defaultCharset();
            ByteBuffer byteBuffer = charset.encode(cipher.elementAt(i));
            int byteCount = fileChannel.write(byteBuffer);
            fileChannel.close();
            String a = cipher.elementAt(i);
            System.out.println("암호문을 c"+i+".txt 에 저장했습니다.");
         }
        saveKeytxt();
    }
    public String makeTxtList() throws IOException{
        String mgslist = "";
        cipher.removeAllElements();

        for(int i = 0; i <10; i++){
            Path path = Paths.get(des+"c"+i+".txt");

            FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.READ);
            ByteBuffer byteBuffer = ByteBuffer.allocate(100);
            Charset charset = Charset.defaultCharset();

            int byteCount;

            while(true){
                 byteCount = fileChannel.read(byteBuffer);
                 if(byteCount == -1) break;
                 byteBuffer.flip();
                 data += charset.decode(byteBuffer).toString();
                 byteBuffer.clear();
            }

            fileChannel.close();
            System.out.println("c"+i+".txt 파일을 보냈습니다.");
            cipher.add((String)data);
            data = "";
            // 암호화 파일을 읽어서 vector에 넣은 후
        }

        for(int i = 0; i < 10; i++){ // 특수 문자로 구분하여 저장
            mgslist += "※";
            mgslist += cipher.elementAt(i);
        }
        return mgslist;
    }
    public void saveKeytxt() throws IOException{
        String msg = sha1.SHA1forAES(password);
        String key = sha1.SHA1forAES(hakbun);

        String ck = aes.encryptAES(msg, key);
        String base64 = Base64.encode(ck.getBytes());

        Path path = Paths.get(des+"key.txt");
        Files.createDirectories(path.getParent());

        FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

        Charset charset = Charset.defaultCharset();
        ByteBuffer byteBuffer = charset.encode((String)base64);
        int byteCount = fileChannel.write(byteBuffer);
        fileChannel.close();
        System.out.println("Ks를 비밀키 화일 key.txt에 저장했습니다.");

    }
    public void keyUpdate() throws IOException{
        String word = "";
        String msg = "";
        String kw = "";
        String Encryptedtoken = "";
        String Ecryptedid = "";

        for(int i = 0; i < textvector.size();i++){
            System.out.println(textvector.elementAt(i));
        }
        loadCK();
        System.out.println("keyUpdate 시작");

        for (int i = 0; i < kword.size(); i++){
            word = kword.elementAt(i); // 저장된 키워드 하나씩
            System.out.println(word+"와 연관된 파일 찾는중");
            for (int j = 0; j < textvector.size(); j++){
                msg = textvector.elementAt(j);
                if(msg.contains(word)){ // 메시지 안에서 키워드를 찾음
                    String cipt = "c"+j+".txt";
                    String token = mysql.makeToken(word,password);
                    kw = calcKW(word);
                    Encryptedtoken = "0"+kw+token;
                    Encryptedtoken = sha1.SHA1(Encryptedtoken);
                    Ecryptedid = "1"+kw+token;
                    Ecryptedid =sha1.SHA1(Ecryptedid);
                    Ecryptedid = xorString(cipt,Ecryptedid);
                    Ecryptedid = Base64.encode(Ecryptedid.getBytes());
                    sendtoken(Encryptedtoken,Ecryptedid);
                    System.out.println(cipt+"에 "+word+"가 포함되어있습니다.");
                }
            }
        }
    }
    public String xorString(String s1, String s2){ // 문자열 간 xor를 위한 함수
           StringBuilder sb = new StringBuilder();
           for(int i=0; i<s1.length() && i<s2.length();i++){
                sb.append((char)(s1.charAt(i) ^ s2.charAt(i)));
           }
            return sb.toString();
    }
   public void sendtoken(String s1, String s2){ //두개의 문자를 서버로 보내줌
        try {
            output.writeUTF("$"+s1+"$"+s2);
        } catch (IOException ex) {
            Logger.getLogger(Fileio.class.getName()).log(Level.SEVERE, null, ex);
        }
   }
    public void loadCK() throws IOException{ //key.txt를 읽어서 저장
        Path path = Paths.get(des+"key.txt");

        FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.READ);
        ByteBuffer byteBuffer = ByteBuffer.allocate(100);
        Charset charset = Charset.defaultCharset();

        int byteCount;

        while(true){
             byteCount = fileChannel.read(byteBuffer);
             if(byteCount == -1) break;
             byteBuffer.flip();
             data += charset.decode(byteBuffer).toString();
             byteBuffer.clear();
        }

        fileChannel.close();
        System.out.println("key.txt 파일을 읽었습니다.");
        ck = data;
        ck = new String(Base64.decode(ck));
    }
    public String calcKW(String word) throws IOException{
        String k = sha1.SHA1(password);
        String ks = aes.decryptAES(k, ck);
        String kw = aes.paddingAES(ks, word);
        return kw;
    }
    public void saveReceiveTxt(String msg) throws IOException{ //서버로 부터 받은 암호화 문서를 복호화함
        String command = "";
        String filename = "";
        String ciphertxt = "";
        String key = sha1.SHA1forAES(password);

        StringTokenizer list = new StringTokenizer(msg);
        while(list.hasMoreTokens()){
            command = list.nextToken("◁");
            filename = command.substring(0, 6);
            ciphertxt = command.substring(6,command.length());
            ciphertxt = ctr.CTRDec(ciphertxt, key);
            System.out.println(ciphertxt);
            saveReceiveFile(filename, ciphertxt);
        }
    }
    public void saveReceiveFile(String file, String msg) throws IOException{ // 복호화한 내용을 문서에 저장
        String filename = file;
        String text = msg;

        Path path = Paths.get(des+"/down/"+filename);
        Files.createDirectories(path.getParent());

        FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

        Charset charset = Charset.defaultCharset();
        ByteBuffer byteBuffer = charset.encode(text);
        int byteCount = fileChannel.write(byteBuffer);
        fileChannel.close();
        System.out.println(filename+"을 저장했습니다.");
    }
}
