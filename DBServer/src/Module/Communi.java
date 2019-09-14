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
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Communi {
    private String des = "C:/Users/jidby/Desktop/Server/";

    Server server = new Server();
    Fileio fio = new Fileio(des);
    sqlcon mysql = new sqlcon();

    public Communi(){
        server.StartServer();
    }
    class Server{
        private ServerSocket Socket;
        private Socket Socket1;
        private final int port = 9882;
        DataOutputStream output;

        public void StartServer(){
                try{
                        mysql.connect();
                        Socket = new ServerSocket(port); // 소켓을 열고
                        System.out.println("클라이언트를 기다리는 중입니다. (포트  : "+port+")");

                        Socket1 = Socket.accept(); // 클라이언트가 들어오면
                        ReceiveThread ReceiveMsg = new ReceiveThread(Socket1);
                        ReceiveMsg.start(); // 메시지 받는 스레드 시작

                        output = new DataOutputStream(Socket1.getOutputStream());
                        System.out.println("클라이언트가 접속하였습니다.");
                }
                catch (IOException e){ System.out.println("포트가 이미 사용 중 입니다."); }
        }
        public void SendMsg(String msg){
            try {
                output.writeUTF(msg);
            } catch (IOException ex) {}
        }
}
    class ReceiveThread extends Thread implements Runnable{
        private Socket Socket;
        DataInputStream input;
        DataOutputStream output;

        public ReceiveThread(Socket Socket) {
                this.Socket = Socket;
                try {
                        input = new DataInputStream(Socket.getInputStream());
                        output = new DataOutputStream(Socket.getOutputStream());
                } catch (IOException e) {}
        }
        public synchronized void run() {
                while (input != null) {
                        try {
                                String msg = input.readUTF();
                                if((msg.charAt(0))=='@'){ // 메시지의 첫 글자로 명령 판단
                                    System.out.println("* 키워드 검색 요청 *");
                                    String idlist = mysql.searchKw(msg);
                                    String list = fio.sendTxtInList(idlist);
                                    output.writeUTF(list);
                                }
                                else if((msg.charAt(0))=='$'){
                                    System.out.println("* 키워드 업데이트 요청 *");
                                    mysql.insertEncrypt(msg);
                                    System.out.println("셋업을 완료했습니다.");
                                    System.out.println("* 클라이언트 명령 대기 중  *");

                                }
                                else if((msg.charAt(0))=='※'){
                                    System.out.println("파일을 클라이언트로부터 받았습니다.");
                                    System.out.println("파일 저장 경로  :"+des);
                                    fio.makeCipTxt(msg);
                                    mysql.makeTable();
                                    System.out.println("셋업을 완료했습니다.");
                                    System.out.println("* 클라이언트 명령 대기 중  *");
                                }
                        }
                        catch (IOException e) {
                            System.out.println("클라이언트가 종료되었습니다.");
                            break;
                        } catch (SQLException ex) {
                        Logger.getLogger(Communi.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
        }
    }
}
