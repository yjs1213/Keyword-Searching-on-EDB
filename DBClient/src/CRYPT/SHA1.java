/*
  정보보호학과 14054027 유지상

  CRYPT/SHA1.java

  문서 FIPS 180-2를 참고하여 구현했습니다.
  간단한 블록 처리를 위해 문자열을 2진수 String으로 변환 후 처리했습니다.

*/
package CRYPT;

import java.util.Arrays;

public class SHA1 {
    int state[] = new int[16]; // 메시지를 블록화해서 저장합니다.
    int h[] = new int[5]; // initial hash value를 저장합니다.
    int block[] = new int[16]; // state에 저장되기 전에 블록을 만들기위해 사용됩니다.
    int w[] = new int[80]; //  message schedule이 저장됩니다.
    public void init(){
         h[0] = 0x67452301;
         h[1] = 0xEFCDAB89;
         h[2] = 0x98BADCFE;
         h[3] = 0x10325476;
         h[4] = 0xC3D2E1F0;

         Arrays.fill(state,0); // 해쉬에 쓰일 배열들을 0으로 초기화 합니다.
         Arrays.fill(block,0);
         Arrays.fill(w,0);
    }
    public String spiltMsg(String str){ //메시지를 블록화합니다.
        String msg = str;
        String binarymsg = "";
        int loop = 0;
        init();

        for(int i = 0; i<msg.length(); i++){ // 메시지를 16진수로 변환해서 binarymsg에 저장합니다.
            binarymsg += String.format("%02X",(int)msg.charAt(i));
        }

        loop = binarymsg.length() / 128; // 길이만큼 loop 횟수를 지정해줍니다.
        if (binarymsg.length()!=112&&binarymsg.length()%128!=0) loop++; // 나누기 특성상 상황별로 loop의 횟수를 1씩 증가시킵니다.
        if (binarymsg.length()==112) loop++;

        // 마지막블록 길이에 따라 처리가 달라지므로 i==loop-1 조건을 확인합니다
        // 1. 마지막 블록의 길이가 128이면
        // 2. 마지막 블록의 길이가 112이면
        // 3. 마지막 블록의 길이가 112보다 크고 128보다 작을때
        // 4~5. 일반적 상황

        for(int i = 0; i < loop; i++){
            if(i==loop-1&&binarymsg.substring(i*128, binarymsg.length()).length()==128){
                test(binarymsg.substring(i*128, binarymsg.length()),2,binarymsg.length()*4);
            }
            else if((i==loop-1&&binarymsg.substring(i*128, binarymsg.length()).length()==112)){
                test(binarymsg.substring(i*128, binarymsg.length()),1,binarymsg.length()*4);
            }
            else if((i==loop-1&&binarymsg.substring(i*128, binarymsg.length()).length()>112&&binarymsg.substring(i*128, binarymsg.length()).length()<128)){
                test(binarymsg.substring(i*128, binarymsg.length()),1,binarymsg.length()*4);
            }
            else if(i==loop-1){
                test(binarymsg.substring(i*128, binarymsg.length()),448,binarymsg.length()*4);
            }
            else{
                test(binarymsg.substring(i*128, i*128+128),512,binarymsg.length()*4);
            }
        }
        return makeHash();
    }
    public void test(String str, int num, int len){
        // 블록의 길이가 112 이거나 128일 경우 추가적인 블록이 발생해서 미리 블록을 만들어 놓습니다.
        int[] block1 = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                                            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
        int[] block2 = {0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                                            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
        int flag = num; // 상황별 처리를 위한 변수
        String HexedString = str; // 파라미터 저장
        int loop = 0;
        String BinedString = "";
        String tmp = "";
        // HexedString 16진수 String -> block에 정수형으로 변환해서 저장 -> BinedString에 2진수로 변환해서 저장 -> state에 정수형으로 변환해서 저장.
        // 쉬운 블록 처리를 위해 여러 변환과정을 거칩니다.....

        loop = HexedString.length()/8;
        if (HexedString.length()%8!=0) loop++;

        for(int i = 0; i<loop;i++){ //block에 정수형 변환해서 저장
            if (i==loop-1) block[i] = Integer.parseUnsignedInt(HexedString.substring(i*8, HexedString.length()),16);
            else block[i] = Integer.parseUnsignedInt(HexedString.substring(i*8, i*8+8),16);
        }

        for(int k = 0; k < loop; k++){ // BinedString에 2진수 string으로 저장
            tmp = Integer.toBinaryString(block[k]);
            while(tmp.length()%8!=0){ // block이 정수형이기 때문에 앞에 0이 사라지므로 추가해줍니다.
                tmp = "0"+tmp;
            }
            BinedString += tmp;
        }

        if(BinedString.length()!=512){ //1을 무조건 패딩합니다. 단, 512비트의 경우 다음 블록에 1이 추가되므로 제외시킵니다.
            BinedString += "1";
            while(BinedString.length()%8!=0) BinedString += "0"; // 0도 패딩해줍니다.
        }
        switch(flag){
            case 1: // 길이가 448비트일때 && 마지막 블록일때
                block1[15] = padlen(len); // 마지막 워드에 메시지 길이를 추가하고
                while(BinedString.length()%448!=0){
                   BinedString += "00000000";
                }
                for(int i = 0; i < 16; i++){ // state에 정수형으로 저장
                    state[i] = Integer.parseUnsignedInt(BinedString.substring(i*32, i*32+32),2);
                }
                calcHash(); // 해시값 계산
                System.arraycopy(block1, 0, state, 0, 16); //block1 을 state에 copy 후
                calcHash(); // 해시값 계산
                break;
            case 2: // 길이가 512비트일때 && 마지막 블록일때
                for(int i = 0; i < 16; i++){
                    state[i] = Integer.parseUnsignedInt(BinedString.substring(i*32, i*32+32),2);
                }

                block2[15] = padlen(len);

                calcHash();
                System.arraycopy(block2, 0, state, 0, 16);
                calcHash();
                break;
            default: //일반적인 상황일때
                while(BinedString.length()%flag!=0){
                   BinedString += "00000000";
                }
                // 16개의 워드중에서 마지막 블록일 경우 끝 두개의 워드는 메시지 길이로 입력이 되는데
                // 길이가 512이면 모두다 채워줘야 하기때문에
                // 반복문의 횟수 설정을 위해 s를 사용하였습니다
                int s = 14;
                if(flag==512) s = 16;
                for(int i = 0; i < s; i++){
                    state[i] = Integer.parseUnsignedInt(BinedString.substring(i*32, i*32+32),2);
                }

                if(flag!=512){
                    state[14] = 0x0000000;
                    state[15] = padlen(len);
                }
                calcHash();
                break;
        }
    }
    public String makeHash(){ // 계산된 해시를 합쳐서 String으로 변환해줍니다.
        String value = "";
        String tmp = "";
        for(int i = 0; i < 5; i++){
            tmp = Integer.toHexString(h[i]);
            while(tmp.length()!=8) tmp="0"+tmp;
            value += tmp;
        }
        return value;
    }
    public int padlen(int len){ // 길이를 16진수로 변환해줍니다.
        String strlen = Integer.toHexString(len);
        return Integer.parseInt(strlen, 16);
    }
    public int ROTL(int value, int bit){ // Circular left shift를 위한 함수입니다.
        int tmp = (value << bit) | (value >>> (32 - bit));
        return tmp;
    }

    public void calcW(){ // w를 계산해줍니다.
        for (int i = 0; i < 80; i++){
            if(i>=0&&i<=15) w[i] = state[i];
            else w[i] = ROTL((w[i-3]^w[i-8]^w[i-14]^w[i-16]),1);
        }
    }
    public void calcHash(){
        int a = h[0];
        int b = h[1];
        int c = h[2];
        int d = h[3];
        int e = h[4];
        int tmp = 0;
        calcW();

        for(int i = 0; i < 80; i++){
            tmp = ROTL(a,5)+calcHashFunc(i,b,c,d)+e+calcK(i)+w[i];
            e = d;
            d = c;
            c = ROTL(b,30);
            b = a;
            a = tmp;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
    public int calcHashFunc(int i, int x, int y, int z){
        int value = 0;

        if(i>=0&&i<20) value = ((x&y)|((~x)&z));
        else if(i>=20&&i<40) value = x^y^z;
        else if(i>=40&&i<60) value = (x&y)|(x&z)|(y&z);
        else if(i>=60&&i<80) value = x^y^z;
        return value;
    }
    public int calcK(int i){ // 라운드 별 상수를 리턴해줍니다.
        int value = 0;

        if(i>=0&&i<20) value = 0x5A827999;
        else if(i>=20&&i<40) value = 0x6ED9EBA1;
        else if(i>=40&&i<60) value = 0x8F1BBCDC;
        else if(i>=60&&i<80) value = 0xCA62C1D6;
        return value;
    }
    public String SHA1(String msg) {
        String Cipher = msg;
        Cipher = spiltMsg(Cipher);
      return Cipher;
    }
    public String SHA1forAES(String msg) {
        String Cipher = msg;
        String key = "";
        Cipher = spiltMsg(Cipher);

       for (int i = 8; i < Cipher.length(); i++){
           key = key +  Cipher.charAt(i);
       }

      return key;
    }
}
