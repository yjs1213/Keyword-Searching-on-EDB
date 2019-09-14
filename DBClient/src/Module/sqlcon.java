/*
  정보보호학과 14054027 유지상

  Module/sqlcon.java

  데이터베이스 처리를 위한 Class입니다.


*/
package Module;

import CRYPT.SHA1;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

public class sqlcon {
        Connection con;
        SHA1 sha1 = new SHA1();
        public void connect(){

            try {
                con = DriverManager.getConnection("jdbc:mysql://localhost:3306/client","root","root");
            } catch (SQLException ex) {
                System.out.println("데이터 베이스 연결 중 오류 발생");
                Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        public void makeTable(){ //테이블 생성을 위한 함수

            String table = "CREATE TABLE kwsearch ("
                + "id INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                + "Keyword varchar(15) NOT NULL,"
                + "Token blob NOT NULL,"
                + "Counter INT(10) NOT NULL,"
                + "Seed timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP)";
            try {

                DatabaseMetaData dbm = con.getMetaData();
                ResultSet tables = dbm.getTables(null, null, "kwsearch", null);
                if (tables.next()) System.out.println("kwsearch 테이블이 이미 존재합니다.");
                else {
                    Statement stmt = con.createStatement();
                    stmt.executeUpdate(table);
                    System.out.println("kwsearch 테이블을 만들었습니다.");
                }
            } catch (SQLException ex) {
                Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        public String makeToken(String word, String pw){
            String password = pw;
            int counter =  100;
            String seed = "";
            String token = "0";

            boolean exist = false;
            try {
                Statement stmt = con.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM kwsearch");
                rs.beforeFirst();
                while(rs.next()){
                    if(word.equals(rs.getString("keyword"))){
                        exist = true;
                    }
                }
            if(exist){ // 키워드가 존재할때
                rs.beforeFirst();
                while(rs.next()){
                    if(word.equals(rs.getString("keyword"))){
                        seed=rs.getString("Seed");
                        counter = rs.getInt("Counter")-1;
                    }
                }
                token = seed + password;
                for(int i = 0; i < counter; i++){
                    token = sha1.SHA1(token);
                }

                String sql = "update kwsearch set Token = '"+token+"' where Keyword = '"+word +"'";
                stmt.executeUpdate(sql);
                sql = "update kwsearch set Counter = '"+counter+"' where Keyword = '"+word +"'";
                stmt.executeUpdate(sql);
            }
            else{ //키워드가 없을때
                String sql = "INSERT INTO kwsearch(Keyword,Token,Counter)" + " VALUES('"+word +"','"+ token +"','"+ counter +"')";
                stmt.executeUpdate(sql);
                ResultSet rss = stmt.executeQuery("SELECT * FROM kwsearch");
                rss.beforeFirst();

                while(rss.next()){
                        if(word.equals(rss.getString("keyword"))){
                                seed=rss.getString("Seed");
                                break;
                        }
                }
                token = seed + password;
                for(int i = 0; i < counter; i++){
                    token = sha1.SHA1(token);
                }
                sql = "update kwsearch set Token = '"+token+"' where Keyword = '"+word +"'";
                stmt.executeUpdate(sql);
            }
            } catch (SQLException ex) {
                Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
            }
            return token;
        }
        public String kwSearch(String word) { //키워드 서치를 위한 함수입니다.
            boolean exist = false;
            String token = "";
            int counter = 0;

            try {
                Statement stmt = con.createStatement();
                ResultSet rs;
                rs = stmt.executeQuery("SELECT * FROM kwsearch");

                rs.beforeFirst();
                while(rs.next()){
                    if(word.equals(rs.getString("keyword"))){
                        exist = true;
                        token = rs.getString("Token");
                        counter = rs.getInt("Counter");
                    }
                }
                if (!exist) return "*";
            } catch (SQLException ex) {
                Logger.getLogger(sqlcon.class.getName()).log(Level.SEVERE, null, ex);
            }
            return "@"+token+"@"+Integer.toString(counter);
        }
}
