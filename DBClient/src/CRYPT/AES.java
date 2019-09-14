/*
  정보보호학과 14054027 유지상

  CRYPT/AES.java

  AES는 현대 암호론 시간에 배운 그대로 구현했습니다.
  SBOX와 GALOIS, RCON은 구글을 참조하였고.
  MixColumn에서 Field 안에서의 계산을 위해 255가 넘어갈 시 256을 빼고 0x1b와 XOR했습니다(구글링).
  복호화 시 미리 키 계산을 했습니다.


*/
package CRYPT;

public class AES {
    private int[][] state =new int[4][4]; // 4x4 행렬로, 메시지가 저장될 행렬입니다.
    private int[][] keyary = new int[4][4]; // 마찬가지로 키가 저장될 행렬입니다.
    private int[][] plaintext = new int[4][4]; // CTR모드시 IV는 state 행렬에 저장되고, 메시지는 여기에 저장됩니다.
    private int[][] prekey = new int[11][16]; // 복호화시 키를 미리 계산하게 되는데 각 행마다 128비트의 키가 저장됩니다.
    private static final int[][] SBOX = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
    private static final int[][] GALOIS = {{0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}};
    private static final int[][] invgalois = {{0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}};
    private static final int[] RCON = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    private static final int[][] invSBOX = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
    private void AESDec(){
        preKeySchedule(); // 복호화시 미리 키 계산을 해줍니다.
        for(int i = 0; i<11;i++){ //0~10라운드까지 반복합니다. i로 라운드를 구별합니다.
            if (i==0){
                bringKey(10-i); // prekey에서 10-i 번째 키를 keyary에 저장합니다.
                addKey();
            }
            else if(i==10){
                invshiftRow();
                invbyteSub();
                bringKey(10-i);
                addKey();
            }
            else{
                invshiftRow();
                invbyteSub();
                bringKey(10-i);
                addKey();
                invMixColumns();
            }
        }
    }
    private void AESEnc(){
        for(int i = 0; i<11;i++){
            if (i==0) addKey();
            else if(i==10){
                byteSub();
                shiftRow();
                keySchedule(i);
                addKey();
            }
            else{
                byteSub();
                shiftRow();
                mixColumn();
                keySchedule(i);
                addKey();
            }
        }
    }
    private void byteSub(){
        int hex;
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++) {
                hex = state[j][i];
                state[j][i] = SBOX[hex / 16][hex % 16];
            }
        }
    }
   private void shiftRow(){
        for(int i = 1; i < 4; i++){
            for(int j = 0; j < i; j++) shiftAry(i);
        }
    }
   private void shiftAry(int row){ // 행 별 쉬프트를 하기 위해 사용됩니다.
       int temp=state[row][0]; // 첫번째 값 저장 후
       for (int i = 1; i < 4; i++) state[row][i-1]=state[row][i]; // 하나씩 옆으로 옮김
       state[row][3]=temp; // 마지막 자리에 첫번째 값 저장
   }
    private int mcCal(int a[], int i){ // 실제 mixColumn 계산을 수행해줍니다. GALOIS을 참고하여 case에 맞는 계산
        int[] ary = new int[4];
        int hex = 0;
        int tmp = 0;
        for (int k = 0; k < 4; k++){
            hex = a[k];
            switch(GALOIS[i][k]){
                case 0x01:
                    ary[k]=hex;
                    break;
                case 0x02:
                    ary[k]=shift(hex);
                    break;
                case 0x03:
                    tmp = hex;
                    hex = shift(hex);
                    ary[k] = tmp ^ hex;
                    break;
            }
        }
        return ary[0]^ary[1]^ary[2]^ary[3]; // 계산 결과 수행 후 서로 xor해서 출력해줍니다.
    }
   private void mixColumn(){
        int[] tmp = new int[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) tmp[j]=state[j][i];
            for (int k = 0; k < 4; k++) state[k][i] = mcCal(tmp, k);
        }
   }
    private void invbyteSub(){
        int hex;
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++) {
                hex = state[j][i];
                state[j][i] = invSBOX[hex / 16][hex % 16];
            }
        }
    }
    private void invshiftRow(){
        for(int i = 1; i < 4; i++){
            for(int j = i; j < 4; j++) shiftAry(i);
        }
    }
    private void invMixColumns() {
        int[] tmp = new int[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) tmp[j]=state[j][i];
            for (int k = 0; k < 4; k++) state[k][i] = invmcCal(tmp, k);
        }
   }
   private int shift(int a){ // field 안에서의 처리를 위해 255를 넘었는지 확인 후 처리를 합니다.
        int hex = a;
        final int carry = 0x1b;
        hex = (hex << 1);
        if(hex>255){
            hex-=256;
            hex ^= carry;
        }
        return hex;
    }
    private int invmcCal(int a[], int i){
        int[] ary = new int[4];
        int original = 0;
        int hex = 0;

        for (int k = 0; k < 4; k++){
            hex = a[k];
            switch(invgalois[i][k]){
              case 0x09:
                    original = hex;
                    hex = shift(hex);
                    hex = shift(hex);
                    hex = shift(hex);
                    ary[k] = hex^original;
                    break;
              case 0x0b:
                    original = hex;
                    hex = shift(hex);
                    hex = shift(hex);
                    hex ^= original;
                    hex = shift(hex);
                    ary[k] = hex^original;
                    break;
              case 0x0d:
                    original = hex;
                    hex = shift(hex);
                    hex ^= original;
                    hex = shift(hex);
                    hex = shift(hex);
                    ary[k] = hex ^ original;
                    break;
              case 0x0e:
                    original = hex;
                    hex = shift(hex);
                    hex ^= original;
                    hex = shift(hex);
                    hex ^= original;
                    ary[k] = shift(hex);
                    break;
            }
        }
        return ary[0]^ary[1]^ary[2]^ary[3];
    }

    private void preKeySchedule(){
        for(int i = 0; i < 16; i++){
            prekey[0][i] = keyary[i/4][i%4];
        }
        for(int i = 1; i < 11; i++){
            keySchedule(i);
            for(int j = 0; j < 16; j++){
                prekey[i][j] = keyary[j/4][j%4];
            }
        }
    }
    private void bringKey(int round){
        for(int i = 0; i < 16; i++){
            keyary[i/4][i%4] = prekey[round][i];
        }
    }
    private void keySchedule(int rc){ //라운드 별 키를 계산해줍니다.
        int[] gen = new int[4];
        for (int i = 0; i < 4; i++) gen[i]=keyary[i][3];

       int temp=gen[0];
       for (int i = 1; i < 4; i++) gen[i-1]=gen[i];
       gen[3]=temp;

       int hex;
       for (int i = 0; i < 4; i++) {
                hex = gen[i];
                gen[i] = SBOX[hex / 16][hex % 16];
       }
       gen[0]^=RCON[rc];
       for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                if(i == 0) keyary[j][0]=keyary[j][0]^gen[j];
                else keyary[j][i]=keyary[j][i]^keyary[j][i-1];
            }
       }
    }
    private void addKey(){
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++) state[j][i]=state[j][i]^keyary[j][i];
        }
    }
    private void printAry(){
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                System.out.format("%02X",state[i][j]);
                System.out.print("  ");
            }
            System.out.println();
        }
    }
    private void printKey(){
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                System.out.format("%02X",keyary[i][j]);
                System.out.print("  ");
            }
            System.out.println();
        }
    }
    private String HextoString(){ //integer를 string으로 변환해줍니다.
        String result = "";

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                if(state[j][i]<16) result = result + 0;
                result = result + Integer.toHexString(state[j][i]);
            }
        }
        return result;
    }
    public String encryptCTR(String iv, String keys, String msg) {
        String ary = iv;
        String key = keys;
        String text = msg;
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[j][i]=Integer.parseInt(ary.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                keyary[j][i]=Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                plaintext[j][i]=Integer.parseInt(text.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        AESEnc();

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++) state[j][i]^=plaintext[j][i];
        }

        return HextoString();
    }
    public String decryptCTR(String iv, String ciphert, String keys){
        String ary = iv;
        String key = keys;
        String text = ciphert;
        String result = "";

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[j][i]=Integer.parseInt(ary.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                keyary[j][i]=Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                plaintext[j][i]=Integer.parseInt(text.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        AESEnc();

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++) state[j][i]^=plaintext[j][i];
        }

        result = HextoString();

        String plain = "";
        for (int i = 0; i < result.length(); i+=2) {
            String str = result.substring(i, i+2);
            plain += (char)Integer.parseInt(str, 16);
        }

        return plain;
    }
    public String encryptAES(String msg, String keys){
        String text = msg;
        String key = keys;

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[j][i]=Integer.parseInt(text.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                keyary[j][i]=Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        AESEnc();

        return HextoString();
    }
    public String decryptAES(String ciphert, String keys){
        String key = keys;
        String text = ciphert;

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[j][i]=Integer.parseInt(text.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                keyary[j][i]=Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        AESDec();

        return HextoString();
    }
    public String paddingAES(String msg,String keys){ // key가 128비트가 안될 시 이것을 사용하여 패딩 후 aes를 합니다.
        String key=keys;
        String padkey = "";
        String result = "";

        while(key.length()%16 != 0) key = key + 0;
        for (int j = 0; j < key.length(); j++) padkey += String.format("%02X", (int) key.charAt(j));

        result = encryptAES(msg,padkey);

        return result;
    }
}
