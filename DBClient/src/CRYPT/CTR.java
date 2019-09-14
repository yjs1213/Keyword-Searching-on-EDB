/*
  정보보호학과 14054027 유지상

  CRYPT/CTR.java

  AES가 128Bit 임에 따라 16Byte로 나누기 위해 부족한 바이트는 0으로 패딩하였고,
  패딩된 0의 개수를 표현하기 위하여 헤더를 구현하였습니다.
  각 메시지 16Byte에서 앞 2Byte는 0의 개수를 표현하고, 나머지 14Byte는 암호화할 메시지로 구성되게 했습니다.
  Initial Vector는 총 16Byte에서 앞 8Byte는 난수를 생성하여 입력하고,
  뒤 8Byte는 00000001부터 블록의 개수만큼 +1 하여 구성되게 했습니다.

*/
package CRYPT;

import java.util.StringTokenizer;
import org.apache.commons.lang3.RandomStringUtils;

public class CTR {
    private String NONCE = "";
    private String iv = "";
    private int count;
    private int pad = 0;
    AES aes = new AES();

    public CTR(){ // 객체 생성 시 알파벳을 랜덤으로 받아서 16진수 처리 후 NOCE에 입력했습니다.
        String generatedString = RandomStringUtils.randomAlphabetic(8);
        for (int j = 0; j < generatedString.length(); j++) NONCE += String.format("%02X", (int) generatedString.charAt(j));
        System.out.println("CTR NONCE 생성을 완료했습니다.");
    }
    private String makeHeader(){ // 0으로 패딩 한 갯수를 나타낸 헤더를 생성 해 줍니다.
        String head = "";
        if (pad<10) head = "0";
        head = head + Integer.toString(pad);

        return head;
    }
    private void makeIV(int i){ // IV에서 뒤 8바이트를 만들어줍니다.
        String charcount = Integer.toString(i);
        String pad = "";

        for(int j = 0; j< (16-charcount.length()); j++) pad = "0"+pad;
        iv = NONCE+pad+charcount;
    }
    public String CTREnc(String msg, String key){
        String Ciphertext = "";
        String header = "";
        String block = "";
        String blocktohex = "";

        pad = 0;
        count = msg.length() / 14; //블록 개수만큼 AES를 하기위해 사용하였습니다.

        if (msg.length()> 14 * count){ //16바이트씩 자르기 위해 0으로 패딩하였습니다.
            while(msg.length()%14 != 0){
                msg = msg + 0;
                pad++;
            }
            count++; //패딩을 하면 블록 개수가 늘어납니다.
        }
        header = makeHeader();

        for(int i = 0; i < count; i++){
            blocktohex = "";
            makeIV(i+1); // 라운드 별 IV를 생성하고,
            block = header + msg.substring(14 * i, 14 * i + 14); //헤더 2바이트와 메시지 14바이트씩 저장합니다.
            for (int j = 0; j < block.length(); j++) blocktohex += String.format("%02X", (int) block.charAt(j)); //block을 16진수화 시키고 저장합니다.
            Ciphertext = Ciphertext + aes.encryptCTR(iv, key, blocktohex); // aes한 결과를 Ciphertext에 Concat 합니다.
        }

        return Ciphertext;
    }
    public String CTRDec(String msg, String key){ // CTR 특성상 암호화와 과정이 비슷하나, 헤더에서 0의 개수를 읽어서 마지막 메시지에서 패딩 한 개수만큼 지웁니다.
        String Ciphertext = msg;
        String keys = key;
        String block = "";
        String plaintext = "";
        String text = "";
        int pad = 0;
        int count = Ciphertext.length() / 32;

        for (int i = 0; i < count; i++){
            makeIV(i+1);
            block = Ciphertext.substring(32 * i, 32 * i + 32);
            plaintext += aes.decryptCTR(iv, block, keys);
        }
        String token = plaintext.substring(0, 2); // 헤더를 저장해서
        pad = Integer.parseInt(token); //Integer로 형 변환
        plaintext = plaintext.substring(0, plaintext.length()-pad); // plaintext에서 0~ 총 길이 - 패딩 된 개수 까지 다시 저장

        StringTokenizer list = new StringTokenizer(plaintext); // 헤더를 토큰화 해서 토큰을 제외한 메시지 저장
        while(list.hasMoreTokens()){
            text += (list.nextToken(token));
        }

        return text;
    }
}
