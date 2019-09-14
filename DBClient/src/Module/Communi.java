/*
  정보보호학과 14054027 유지상

  Module/Communi.java

  통신을 위한 Class입니다.
  소켓을 개방하면 클라이언트와 서버는 그 소켓을 받아서 메시지를 주고받기 위한 Thread를 생성합니다.
  클라이언트와 서버 간 통신에서 명령 구분은 문자열의 앞 글자로 구분하였습니다.


*/
package Module;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

public class Communi {
    private Socket socket;
    private final String ip="127.0.0.1";
    private final int port=9882;
    private String msg = "";
    private String des = "C:/Users/jidby/Desktop/java/";
    private DataOutputStream output;
    private DataInputStream input;
    private String hakbun = "";
    private String password = "";
    sqlcon mysql = new sqlcon();
    Fileio fio = new Fileio(des);

    public Communi(){
        Client client = new Client();
        client.start();
        mysql.connect();
        System.out.println("데이터 베이스와 연결 되었습니다.");
    }
    public void print(){
                System.out.println("");
                System.out.println("Client");
                System.out.println("1. Setup");
                System.out.println("2. Keyword Update");
                System.out.println("3. Keyword Search");
                System.out.println("4. Exit");
                System.out.print("Command  :  ");
    }
    public void SendMsg(String msg) throws IOException{
            output.writeUTF(msg);
    }
    public void SetUp(int flag, String SN, String PW) throws IOException{
        String msg = "";
        hakbun = SN;
        password = PW;

        System.out.println("* 셋업 과정 진행 *");
        System.out.println("\n텍스트 파일 저장 경로 :"+des);
        fio.loadPlainTxt();
        fio.saveCipTxt(hakbun,password,output);
        fio.loadKeyword();
        msg = fio.makeTxtList();
        SendMsg(msg);
        mysql.makeTable();
        System.out.println("셋업을 완료했습니다.");
        print();
    }
    public void KeyUpdate(int flag) throws IOException{
        System.out.println("* Key Update 과정 진행 *");
        fio.keyUpdate();
        print();
    }
    public void KeySearch(int flag) throws IOException{
        System.out.println("* Key Search 과정 진행 *");
        Scanner sc = new Scanner(System.in);
        while(true){
            System.out.println("찾을 KEYWORD 를 입력하세요");
            String word = sc.next();
            String exist = mysql.kwSearch(word);
            if(exist.charAt(0)=='*'){
                System.out.println("없는 KEYWORD 입니다.");
            }
            else{
                String kw = fio.calcKW(word);
                output.writeUTF(exist+"@"+kw);
                break;
            }
        }
    }
    class Client{
        public void start(){
            try {
                    socket = new Socket(ip, port); // 서버에 연결하고
                    output = new DataOutputStream(socket.getOutputStream()); // output과
                    input = new DataInputStream(socket.getInputStream()); // input 저장.
                    System.out.println("서버와 연결되었습니다.");
                    ReceiveThread rt = new ReceiveThread(); // 메시지를 받는 쓰레드 생성
                    rt.start();
            }catch (IOException e) {
                System.out.println("서버를 먼저 실행 해 주세요.");
                System.exit(0);
            }
         }
    }
    class ReceiveThread extends Thread implements Runnable{
        public void run() {
                while (true) {
                        try {
                                msg = input.readUTF();
                                if ((msg.charAt(0))=='◁'){ // 받은 메시지의 앞글자로 명령 판단
                                    fio.saveReceiveTxt(msg);
                                }
                        } catch (IOException e) {
                                System.out.println("서버와 소켓 연결이 해제되었습니다.");
                                break;
                        }
                }
        }
    }
}
