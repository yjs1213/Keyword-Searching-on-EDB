/*
  정보보호학과 14054027 유지상

  Module/Fileio.java

  파일 입출력을 위한 Class입니다. NIO 기반으로 구현하였습니다.


*/
package Module;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.StringTokenizer;
import java.util.Vector;

public class Fileio {
    private String des = "";
    private Vector<String> cipher = new Vector<String>();

    public Fileio(String destination){
        des = destination;
    }
    public void makeCipTxt(String msg) throws IOException{ // 특수문자로 구분된 암호문을 쪼개서 벡터에 넣음
        StringTokenizer list = new StringTokenizer(msg);
        while(list.hasMoreTokens()){
            cipher.add(list.nextToken("※"));
        }
        makeTxt();
    }
    public void makeTxt() throws IOException{
        for(int  i = 0; i < 10; i++){
            Path path = Paths.get(des+"c"+i+".txt");
            Files.createDirectories(path.getParent());

            FileChannel fileChannel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

            Charset charset = Charset.defaultCharset();
            ByteBuffer byteBuffer = charset.encode(cipher.elementAt(i));
            int byteCount = fileChannel.write(byteBuffer);
            fileChannel.close();
            System.out.println("c"+i+".txt을 저장했습니다.");
         }
    }
    public String sendTxtInList(String msg) throws IOException{ // 특수문자로 구분된 리스트를 쪼개서
        Vector<String> idList = new Vector<String>();           // 해당하는 파일을 읽어서 클라이언트에 보냄
        String sendlist = "";
        String data = "";

        StringTokenizer list = new StringTokenizer(msg);
        while(list.hasMoreTokens()){
            idList.add(list.nextToken("%"));
        }

        for(int i = 0; i < idList.size(); i++){
            Path path = Paths.get(des+idList.elementAt(i));

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
            sendlist = sendlist + "◁"+ idList.elementAt(i) + data;
            data = "";
            fileChannel.close();
            System.out.println(idList.elementAt(i)+"파일을 보냈습니다.");
        }

        return sendlist;
    }
}
