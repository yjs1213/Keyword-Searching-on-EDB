/*
  정보보호학과 14054027 유지상

  Module/sqlcon.java

  데이터베이스 처리를 위한 Class입니다.


*/
package Module;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

public class sqlcon {
        Connection con;

        public void connect(){
            try {
                con = DriverManager.getConnection("jdbc:mysql://localhost:3306/server","root","root");
            } catch (SQLException ex) {
                System.out.println("데이터 베이스 연결 중 오류 발생");
                Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("데이터 베이스와 연결 되었습니다.");
        }
        public void makeTable(){
            String table = "CREATE TABLE efiles ("
                + "id INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                + "EncryptedToken blob NOT NULL,"
                + "EncryptedID blob NOT NULL)";
            try {

                DatabaseMetaData dbm = con.getMetaData();
                ResultSet tables = dbm.getTables(null, null, "efiles", null);
                if (tables.next()) System.out.println("efiles 테이블이 이미 존재합니다.");
                else {
                    Statement stmt = con.createStatement();
                    stmt.executeUpdate(table);
                    System.out.println("efiles 테이블을 만들었습니다.");
                }
            } catch (SQLException ex) {
                Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        public void insertEncrypt(String msg) throws SQLException{
            Vector<String> text = new Vector<String>();

           StringTokenizer list = new StringTokenizer(msg);
           while(list.hasMoreTokens()){
               text.add(list.nextToken("$"));
           }
           System.out.println("암호화 토큰을 받았습니다.");
           String sql = "INSERT INTO efiles(EncryptedToken,EncryptedID)" + " VALUES('"+text.elementAt(0) +"','"+ text.elementAt(1) +"')";
           Statement stmt = con.createStatement();
           stmt.executeUpdate(sql);
           System.out.println("암호화 토큰을 INSERT INTO efiles 했습니다.");
        }
        public String searchKw(String msg){
            SHA1 sha1 = new SHA1();
            Vector<String> text = new Vector<String>();
            StringTokenizer list = new StringTokenizer(msg);
            while(list.hasMoreTokens()){ // 구분된 명령을 쪼개서 벡터에 넣고
                text.add(list.nextToken("@"));
            }
            String id = "";
            String idlist = "";
            String EncryptedToken = "";
            String Encryptedid = "";
            String token = text.elementAt(0); // 한개씩 변수에 저장
            int counter = Integer.parseInt(text.elementAt(1));
            String kw = text.elementAt(2);

            for(int i = counter; i < 101; i++){
                EncryptedToken = sha1.SHA1("0"+kw+token);
                id = sha1.SHA1("1"+kw+token); // 토큰과 아이디 계산
                try {
                    Statement stmt = con.createStatement();
                    ResultSet rs;
                    rs = stmt.executeQuery("SELECT * FROM efiles");

                    rs.beforeFirst();
                    while(rs.next()){
                        if(EncryptedToken.equals(rs.getString("EncryptedToken"))){
                            Encryptedid = rs.getString("EncryptedID");
                        } // 계산된 토큰과 일치하는게 있으면 아이디 저장
                    }
                    String decodeid = new String(Base64.decode(Encryptedid)); // base64 decoding 하고
                    id = xorString(decodeid,id); // xor

                    System.out.println(id+"를 찾았습니다.");
                    token = sha1.SHA1(token);
                    idlist += "%"+id; // idlist에 파일 이름 concat

                } catch (SQLException ex) {
                    Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
                }
        }
        return idlist;
    }
    public String xorString(String s1, String s2){
          StringBuilder sb = new StringBuilder();
            for(int i=0; i<s1.length() && i<s2.length();i++){
             sb.append((char)(s1.charAt(i) ^ s2.charAt(i)));
            }
          return sb.toString();
    }
}
