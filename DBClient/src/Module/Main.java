package Module;
import java.io.IOException;
import java.util.Scanner;

public class Main {
      public static void main(String[] args) throws IOException {
          int command;
          String SN = "";
          String PW = "";
          boolean loop = true;
          Communi com = new Communi();
          Scanner sc = new Scanner(System.in);
          System.out.println("* GradeuateProject 2018 Keyword search on Encrypted Databases *");
          
          System.out.println("학번을 입력해주세요.");
          SN = sc.next();          
          System.out.println("비밀번호을 입력해주세요.");
          PW = sc.next();

          com.print();
          while(loop){

                command = sc.nextInt();
                switch(command){
                    case 1:
                        com.SetUp(0,SN,PW);
                        break;
                    case 2:
                        com.KeyUpdate(0);
                        break;
                    case 3:
                        com.KeySearch(0);
                        break;
                    case 4:
                        loop = false;
                        break;
                    default:
                }
          }
          System.out.println("BYE!");
          
          System.exit(0);
      }
}
