/*
KhadashPay
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/KhadashPay
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
https://github.com/miguelbalboa/rfid
https://github.com/intrbiz/arduino-crypto
https://github.com/Chris--A/Keypad
*/
#include <SoftwareSerial.h>
SoftwareSerial mySerial(35, 25); // PS/2 Keyboard
SoftwareSerial mySerial1(21, 25); // 4x4 matrix keyboard
SoftwareSerial mySerial2(34, 25); // RFID reader
#include <SoftwareSerial.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "blowfish.h"
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"
#include <sys/random.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "GBUS.h"
#include "Crypto.h"
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#include <Adafruit_ST7735.h>
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

#define TFT_CS1         5
#define TFT_RST1        19
#define TFT_DC1         22
Adafruit_ST7735 operator_tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);
GBUS bus(&mySerial, 3, 10);
GBUS bus1(&mySerial1, 4, 10);
GBUS bus2(&mySerial2, 5, 16);
char ch;
int pr_key;
int cur_pos;
int num_of_IDs;
int count;
byte tmp_st[8];
char temp_st_for_pp[16];
int m;
String dec_st;
String dec_tag;
int decract;
String keyb_inp;
uint8_t back_key[32];
uint8_t back_s_key[32];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
Blowfish blowfish;
String rec_ID;

String space_and_currency = " USD"; // Space + Currency name
int text_size_for_sale = 3;
const int decimal_spaces_in_balance = 2; // determines the number of the decimal spaces in the balance

byte hmackey[] = {"8NYz0Uk9fsYgGg0ew1TuWn8a3vWR2I8Z43917PGtXQici6ud4OGpjI83Si7JWdK7iUUrfSO1s09Sh0mGq5Lyd6ZhcRQRZ7mq1l93MfDbbVuouksd91b9HnVP4h3E0X18i638QM1AAT7Hgqk2pyL41NaK3119Plc9Fk40Z1HxYo58JvviDmbUPvg7S3C7HJZMDO2QvRak9qdL5hsQWEXuci2kg56Ul6Sw1yTrJfTyc8UXh7Y47MoEz6Sa8x83gtp7RN4lu19Dt2"};
unsigned char Blwfsh_key[] = {
0xb5,0x81,0x1a,0x7a,
0xc6,0xb3,0x7a,0x1a,
0xcf,0xc1,0xa7,0x03,
0xde,0xba,0xb9,0xba,
0xe7,0x8c,0x71,0xf3,
0xfe,0xb2,0xd5,0xed
};
uint8_t key[32] = {
0xbe,0x1f,0x5a,0xa2,
0xf2,0xd0,0xad,0xbe,
0x8b,0x24,0xb5,0x73,
0xf8,0x6a,0x9b,0xcd,
0x4b,0xd2,0x45,0x41,
0xbb,0xf2,0xab,0x84,
0x13,0x96,0xc4,0xd1,
0x4b,0x32,0xc6,0xd1
};
uint8_t serp_key[32] = {
0xb9,0x3d,0xf2,0x37,
0xa7,0x6e,0x20,0xd0,
0xe8,0x86,0x4c,0x1b,
0xf4,0x1f,0x96,0xe6,
0xfa,0x1c,0x9f,0x84,
0xe2,0xd9,0x25,0x5e,
0xfa,0xb2,0x9f,0x7d,
0xed,0x89,0x5e,0x57
};
uint8_t second_key[32] = {
0xd2,0xca,0xf8,0xb7,
0xed,0x8e,0xfd,0x38,
0x25,0xd0,0x14,0xed,
0x29,0x9c,0xda,0x68,
0x1b,0x17,0xeb,0xa5,
0xd4,0xf9,0xc8,0xa2,
0x1a,0xee,0x1a,0x3c,
0x34,0x6e,0x9b,0x2d
};

struct myStruct {
  char x;
};

struct myStruct2 {
  char x[4];
};

int clb_m;

String dbase_name = "/spiffs/Accounts.db";

const char* data = "Callback function called";
static int callback(void *data, int argc, char **argv, char **azColName) {
   int i;
   if (clb_m == 0) //Print in serial
    Serial.printf("%s: ", (const char*)data);
   if (clb_m == 1){ //Print in tft
    operator_tft.printf("%s:\n", (const char*)data);
   }
   for (i = 0; i<argc; i++){
       if (clb_m == 0){ //Print in serial
        Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "Empty");
        Serial.printf("\n\n");
       }
       if (clb_m == 1){ //Print in tft
        operator_tft.printf("\n%s = %s\n", azColName[i], argv[i] ? argv[i] : "Empty");
        Serial.printf("\n\n");
       }
       if (clb_m == 2){ //Decrypt
        int ct_len = strlen(argv[i]) + 1;
        char ct_array[ct_len];
        snprintf(ct_array, ct_len, "%s", argv[i]);
        int ext = 0;
        count = 0;
        bool ch = false;
        while(ct_len > ext){
        if(count%2 == 1 && count !=0)
          ch = true;
        else{
          ch = false;
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
        }
        split_dec(ct_array, ct_len, 0+ext, ch, true);
        ext+=32;
        count++;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
       }
       if (clb_m == 3){ //Extract IDs
        int ct_len = strlen(argv[i]) + 1;
        char ct_array[ct_len];
        snprintf(ct_array, ct_len, "%s", argv[i]);
        for (int i = 0; i<ct_len; i++){
          dec_st += ct_array[i];
        }
        dec_st += "\n";
        num_of_IDs++;
       }
   }
   return 0;
}

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes, bool out_f){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for(int i = 0; i < 8; i++){
      t_encr[i] = (unsigned char)plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_aes[16];
  for(int i = 0; i < 8; i++){
      encr_for_aes[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for(int i = 8; i < 16; i++){
      encr_for_aes[i] = get_certain_number();
  }
  /*
  Serial.println("\nFor AES");
  for (int i = 0; i < 16; i++){
    Serial.print(int(encr_for_aes[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  encr_AES(encr_for_aes, add_aes, out_f);
}

void encr_AES(char t_enc[], bool add_aes, bool out_f){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[2]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = get_certain_number();
    R_half[i] = get_certain_number();
  }
  serp_enc(L_half, add_aes, out_f);
  serp_enc(R_half, add_aes, out_f);
}

void serp_enc(char res[], bool add_aes, bool out_f){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  if(add_aes == false){
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
  if(add_aes == true)
  encr_sec_AES(ct2.b, out_f);
  }
}

void encr_sec_AES(byte t_enc[], bool out_f){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[2]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; i++) {
    if (out_f == false)
      Serial.printf("%02x", cipher_text[i]);
    if (out_f == true){
      if (cipher_text[i] < 16)
        dec_st += 0;
      dec_st +=  String(cipher_text[i], HEX);
    }
  }
}

void split_dec(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[2]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char)ret_text[i];
      }
      }
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES_and_blwfsh(ct2.b);
    }
  }
}

void decr_AES_and_blwfsh(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(ret_text[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[2]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      /*
      Serial.println("\nDec by AES");
      for (int i = 0; i < 16; i++){\
        Serial.print(int(ret_text[i]));
        Serial.print(" ");
      }
      Serial.println();
      */
      unsigned char dbl[8];
      for (int i = 0; i < 8; i++){
        dbl[i] = (unsigned char)int(ret_text[i]);
      }
      /*
      Serial.println("\nConv for blowfish");
      for (int i = 0; i < 8; i++){\
        Serial.print(dbl[i]);
        Serial.print(" ");
      }
      Serial.println();
      */
      blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
      blowfish.Decrypt(dbl, dbl, sizeof(dbl));
      /*
      Serial.println("\nDecr by blowfish");
      for (int i = 0; i < 8; i++){\
        Serial.print(int(dbl[i]));
        Serial.print(" ");
      }
      Serial.println();
      */
      if (decract < 4){
        for (int i = 0; i < 8; i++){
          if (dbl[i]<0x10)
            dec_tag += 0;
          dec_tag += String(dbl[i], HEX);
        }
      }
      else{
        for (i = 0; i < 8; ++i) {
          dec_st += (char(dbl[i]));
        }
      }
      decract ++;
}

void gen_rand_ID(int n_itr){
  for (int i = 0; i<n_itr; i++){
    int r_numb3r = esp_random()%95;
    if (r_numb3r != 7)
      rec_ID += char(32 + r_numb3r);
    else
      rec_ID += char(33 + r_numb3r + esp_random()%30);
  }
}

int get_certain_number(){
  return 50;
}

int db_open(const char *filename, sqlite3 **db) {
   int rc = sqlite3_open(filename, db);
   if (rc) {
       if (clb_m == 0) //Print in serial
        Serial.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       if (clb_m == 1) //Print in tft
        operator_tft.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       return rc;
   } else {
       if (clb_m == 0) //Print in serial
        Serial.printf("Opened database successfully\n");
       if (clb_m == 1) //Print in tft
        operator_tft.printf("Opened db successfully\n");
   }
   return rc;
}

char *zErrMsg = 0;
int db_exec(sqlite3 *db, const char *sql) {
   int rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
   if (rc != SQLITE_OK) {
       if (clb_m == 0) //Print in serial
        Serial.printf("SQL error: %s\n", zErrMsg);
       if (clb_m == 1) //Print in tft
        operator_tft.printf("SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
   } else {
       if (clb_m == 0) //Print in serial
        Serial.printf("Operation done successfully\n");
       if (clb_m == 1) //Print in serial
        operator_tft.printf("Oper. done successfully\n");
   }
   return rc;
}

void back_k(){
  for(int i = 0; i<32; i++){
    back_key[i] = key[i];
  }
}

void rest_k(){
  for(int i = 0; i<32; i++){
    key[i] = back_key[i];
  }
}

void back_serp_k(){
  for(int i = 0; i<32; i++){
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k(){
  for(int i = 0; i<32; i++){
    serp_key[i] = back_serp_key[i];
  }
}

void back_s_k(){
  for(int i = 0; i<32; i++){
    back_s_key[i] = second_key[i];
  }
}

void rest_s_k(){
  for(int i = 0; i<32; i++){
    second_key[i] = back_s_key[i];
  }
}

void back_Blwfsh_k(){
  for(int i = 0; i < 16; i++){
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Blwfsh_k(){
  for(int i = 0; i < 16; i++){
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void incr_key() {
  if (key[15] == 255) {
    key[15] = 0;
    if (key[14] == 255) {
      key[14] = 0;
      if (key[13] == 255) {
        key[13] = 0;
        if (key[12] == 255) {
          key[12] = 0;

          if (key[11] == 255) {
            key[11] = 0;
            if (key[10] == 255) {
              key[10] = 0;
              if (key[9] == 255) {
                key[9] = 0;
                if (key[8] == 255) {
                  key[8] = 0;

                  if (key[7] == 255) {
                    key[7] = 0;
                    if (key[6] == 255) {
                      key[6] = 0;
                      if (key[5] == 255) {
                        key[5] = 0;
                        if (key[4] == 255) {
                          key[4] = 0;

                          if (key[3] == 255) {
                            key[3] = 0;
                            if (key[2] == 255) {
                              key[2] = 0;
                              if (key[1] == 255) {
                                key[1] = 0;
                                if (key[0] == 255) {
                                  key[0] = 0;
                                } else {
                                  key[0]++;
                                }
                              } else {
                                key[1]++;
                              }
                            } else {
                              key[2]++;
                            }
                          } else {
                            key[3]++;
                          }

                        } else {
                          key[4]++;
                        }
                      } else {
                        key[5]++;
                      }
                    } else {
                      key[6]++;
                    }
                  } else {
                    key[7]++;
                  }

                } else {
                  key[8]++;
                }
              } else {
                key[9]++;
              }
            } else {
              key[10]++;
            }
          } else {
            key[11]++;
          }

        } else {
          key[12]++;
        }
      } else {
        key[13]++;
      }
    } else {
      key[14]++;
    }
  } else {
    key[15]++;
  }
}

void incr_second_key() {
  if (second_key[0] == 255) {
    second_key[0] = 0;
    if (second_key[1] == 255) {
      second_key[1] = 0;
      if (second_key[2] == 255) {
        second_key[2] = 0;
        if (second_key[3] == 255) {
          second_key[3] = 0;
          if (second_key[4] == 255) {
            second_key[4] = 0;
            if (second_key[5] == 255) {
              second_key[5] = 0;
              if (second_key[6] == 255) {
                second_key[6] = 0;
                if (second_key[7] == 255) {
                  second_key[7] = 0;
                  if (second_key[8] == 255) {
                    second_key[8] = 0;
                    if (second_key[9] == 255) {
                      second_key[9] = 0;
                      if (second_key[10] == 255) {
                        second_key[10] = 0;
                        if (second_key[11] == 255) {
                          second_key[11] = 0;
                          if (second_key[12] == 255) {
                            second_key[12] = 0;
                            if (second_key[13] == 255) {
                              second_key[13] = 0;
                              if (second_key[14] == 255) {
                                second_key[14] = 0;
                                if (second_key[15] == 255) {
                                  second_key[15] = 0;
                                } else {
                                  second_key[15]++;
                                }
                              } else {
                                second_key[14]++;
                              }
                            } else {
                              second_key[13]++;
                            }
                          } else {
                            second_key[12]++;
                          }
                        } else {
                          second_key[11]++;
                        }
                      } else {
                        second_key[10]++;
                      }
                    } else {
                      second_key[9]++;
                    }
                  } else {
                    second_key[8]++;
                  }
                } else {
                  second_key[7]++;
                }
              } else {
                second_key[6]++;
              }
            } else {
              second_key[5]++;
            }
          } else {
            second_key[4]++;
          }
        } else {
          second_key[3]++;
        }
      } else {
        second_key[2]++;
      }
    } else {
      second_key[1]++;
    }
  } else {
    second_key[0]++;
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
  }
}

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;

          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;

                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;

                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }

                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }

                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }

        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
}

size_t hex2bin (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)serp_key[i];
  }
  return 32;
}

void disp_centered_text_on_op(String t_disp, int y){
   int16_t x1, y1;
   uint16_t w, h;
   operator_tft.getTextBounds(t_disp, 160, 0, &x1, &y1, &w, &h);
   operator_tft.setCursor(80 - (w / 2), y);
   operator_tft.print(t_disp);
}

void disp_centered_text_on_cl(String t_disp, int y){
   int16_t x1, y1;
   uint16_t w, h;
   tft.getTextBounds(t_disp, 320, 0, &x1, &y1, &w, &h);
   tft.setCursor(160 - (w / 2), y);
   tft.print(t_disp);
}

void modify_keys(char card1[], int card2[], int card3[], int card4[]){
  int str_len = keyb_inp.length() + 1;
  char input_arr[str_len];
  keyb_inp.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < 2; i++) {
      str += card1[i];
    }
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[16];
  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, i, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;
  for (i = 0; i < 1; i++) {
    hex2bin(key);
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];
    serpent_setkey( & skey, key);
    for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
      if ((j % 8) == 0) putchar('\n');
    }
    for (int i = 0; i < 16; i++)
      ct2.b[i] = res[i];
  }

  unsigned char tblw[16];
  /*
  Serial.println("\nBefore going through Serpent");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 176; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nAfter going through Serpent 176 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 4; i++)
    tblw[i] = ct2.b[i];
    
  for (int i = 0; i < 711; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nAfter going through Serpent 887 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 4; i++)
    tblw[i+4] = ct2.b[i];

  for (int i = 0; i < 4; i++)
    ct2.b[i+6] ^= card2[i];

  for (int i = 0; i < 1773; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nAfter going through Serpent 2660 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 4; i++)
    tblw[i+8] = ct2.b[i];
  // Fill the last four slots in tblw with card
  for (int i = 0; i < 4; i++)
    tblw[i+12] = card3[i];
  
  /*
  Serial.println("\nBefore going through blowfish");
  for (int i = 0; i < 16; i++){
    Serial.print(int(tblw[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  for (int i = 0; i < 654; i++)
    blowfish.Decrypt(tblw, tblw, sizeof(tblw));

  int aft654[2];
  aft654[0] = int(tblw[14]);
  aft654[1] = int(tblw[5]);
  for (int i = 0; i < 1000; i++){
    blowfish.Decrypt(tblw, tblw, sizeof(tblw));
    incr_Blwfsh_key();
  }
  /*
  Serial.println("\nAfter going through blowfish 1654 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(tblw[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  std::string str1 = "";
  for (int i = 0; i < 5; i++) {
    str1 += char(250+i);
  }
    
  for (int i = 0; i < 16; i++) {
    str1 += (char)tblw[i];
  }

  for (int i = 2; i < 4; i++)
    str1 += card1[i];

  for (int i = 34; i < 60; i++)
    str1 += h_array[i];
  
  String h1 = sha512(str1).c_str();
  int h1_len = h1.length() + 1;
  //Serial.print("h1_len: ");
  //Serial.println(h1_len);
  char h1_array[h1_len];
  h1.toCharArray(h1_array, h1_len);
  byte res1[24];
  for (int i = 16; i < 64; i += 2) {
      if (h1_array[i] != 0 && h1_array[i + 1] != 0)
        res1[i / 2] = 16 * getNum(h1_array[i]) + getNum(h1_array[i + 1]);
      if (h1_array[i] != 0 && h1_array[i + 1] == 0)
        res1[i / 2] = 16 * getNum(h1_array[i]);
      if (h1_array[i] == 0 && h1_array[i + 1] != 0)
        res1[i / 2] = getNum(h1_array[i + 1]);
      if (h1_array[i] == 0 && h1_array[i + 1] == 0)
        res1[i / 2] = 0;
  }
  /*
  Serial.println("\n----------What can be used----------");
  Serial.println("\nHashed Blowfish output");
  for (int i = 3; i < 24; i++){
    if (i != 5 && i != 6 && i != 7){
      Serial.print(((int(res1[i]) + 1) * (int(h_array[80 + i]) + 1)) % 256);
      Serial.print(" ");
    }
  }
  Serial.println();
  */
  int tmp_fr_srp[16];
  for (int i = 0; i < 16; i++)
    tmp_fr_srp[i] = ct2.b[i];
  tmp_fr_srp[6] = int(res1[1]);
  // Fill the first four slots in ct2.b with card
  for (int i = 0; i < 4; i++)
    ct2.b[i] = card4[i];

  for (int i = 4; i < 16; i++)
    ct2.b[i] = tmp_fr_srp[i];
    
  for (int i = 0; i < 2000; i++){
    incr_serp_key();
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  }
  /*
  Serial.println("\nFirst three of tmp_f_s");
  for (int i = 0; i < 3; i++){
    if (i == 0)
      Serial.print(tmp_fr_srp[i] ^ aft654[1]);
    else
      Serial.print(tmp_fr_srp[i] ^ int(h_array[60+i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  /*
  Serial.println("\nResult from Serpent");
  for (int i = 2; i < 13; i++){
    Serial.print((((int(ct2.b[i]) + 1) * (int(h1_array[70 + i])) + 2)) % 256);
    Serial.print(" ");
  }
  Serial.println();
  */
  //Serial.print("\nVerifcation number: ");
  unsigned int vn = ((((int(tblw[0]) + 1) * (int(ct2.b[15]) + 2)) * 36 * (int(res1[2]) + 1) + aft654[0] + ((int(h_array[110]) + 1) * (int(h1_array[110]) + 1))) % 9981) + 13;
  //Serial.println(vn);
  /*
  Serial.println("Decomposed");
  Serial.println(int(tblw[0]));
  Serial.println(int(ct2.b[15]));
  Serial.println(int(res1[2]));
  Serial.println(int(aft654[0]));
  Serial.println();
  */
  keyb_inp = "";

  for (int i = 0; i < 8; i++){
    Blwfsh_key[i] = (unsigned char) (((int(res1[i+8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
  }

  for (int i = 0; i < 4; i++){
    second_key[i] = byte(((int(res1[i+18]) + 1) * (int(h_array[98 + i]) + 1)) % 256);
  }
  
  for (int i = 0; i < 3; i++){
    key[i] = byte(tmp_fr_srp[i] ^ int(h_array[60+i]));
  }
  
  key[5] = byte(((int(res1[i]) + 1) * (int(h_array[80 + i]) + 1)) % 256);
  
  for (int i = 2; i < 8; i++){
    second_key[i+8] = byte((((int(ct2.b[i]) + 1) * (int(h1_array[70 + i])) + 2)) % 256);
  }
  
  Blwfsh_key[11] = byte((((int(ct2.b[11]) + 1) * (int(h1_array[81])) + 2)) % 256);

  byte res12[3];
  for (int i = 104; i < 110; i += 2) {
      if (h1_array[i] != 0 && h1_array[i + 1] != 0)
        res12[i / 2] = 16 * getNum(h1_array[i]) + getNum(h1_array[i + 1]);
      if (h1_array[i] != 0 && h1_array[i + 1] == 0)
        res12[i / 2] = 16 * getNum(h1_array[i]);
      if (h1_array[i] == 0 && h1_array[i + 1] != 0)
        res12[i / 2] = getNum(h1_array[i + 1]);
      if (h1_array[i] == 0 && h1_array[i + 1] == 0)
        res12[i / 2] = 0;
  }

  String thmac;
  for(int i = 8; i < 11; i++){
    thmac += (char((((int(ct2.b[i]) + 9) * (int(h1_array[70 + i])) + 3)) % 256));
  }
  thmac += "1f32+=c";
  thmac += char(tmp_fr_srp[0] ^ aft654[1]);
  thmac += (char(((int(res1[3]) + 1) * (int(h_array[84]) + 1)) % 256));
  thmac += (char(((int(res1[4]) + 1) * (int(h_array[85]) + 1)) % 256));
  thmac += (char(card1[1]));
  thmac += "4.[x";
  thmac += (char(card3[2]));
  thmac += char((((int(ct2.b[11]) + 1) * (int(h1_array[81])) + 2)) % 256);
  thmac += char(((int(res1[22]) + 1) * (int(h_array[102]) + 1)) % 256);
  for (int i = 8; i<10; i++){
    thmac += char(((int(res1[i+8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
  }
  thmac += "FFFF";
  /*
  for (int i = 0; i < thmac.length(); i++){
    Serial.println(int(thmac.charAt(i)));
  }
  */
  int thmac_len = thmac.length() + 1;
  char thmac_array[thmac_len];
  thmac.toCharArray(thmac_array, thmac_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(thmac_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  key[9] = authCode[0];
  key[12] = authCode[1];
  Blwfsh_key[11] = authCode[2];
  for (int i = 3; i < 16; i++){
    serp_key[i] = authCode[i];
  }
  for (int i = 0; i < 10; i++){
    hmackey[i] = authCode[i + 16];
  }
  /*
  String res_hash;
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += '0'; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  Serial.println(res_hash);
  for(int i = 0; i<10; i++){
      if (hmackey[i]<0x10) { Serial.print("0"); }{
        Serial.print(String(authCode[i], HEX));
      }
  }
  */
  keyb_inp = "";
  operator_tft.fillScreen(0x1557);
  operator_tft.fillRect(18, 18, 124, 92, 0x08c5);
  operator_tft.setTextColor(0x1557, 0x08c5);
  operator_tft.setTextSize(1);
  disp_centered_text_on_op("Keys derived", 24);
  disp_centered_text_on_op("successfully.", 34);
  operator_tft.setTextColor(0xffff, 0x08c5);
  operator_tft.setTextSize(1);
  disp_centered_text_on_op("Verific. number is", 50);
  operator_tft.setTextSize(2);
  disp_centered_text_on_op(String(vn), 64);
  operator_tft.setTextColor(0x1557, 0x08c5);
  operator_tft.setTextSize(1);
  disp_centered_text_on_op("Press any key to get", 88);
  disp_centered_text_on_op("to the main menu.", 98);
  while (!bus.gotData()){
      bus.tick();
  }
  disp_inact_inscr();
  create_accounts_table();
  m_menu_rect(); main_menu(cur_pos);
  //Serial.println(dbase_name);
}

void disp_inact_inscr(){
  tft.setTextSize(4);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff, 0x155b);
  disp_centered_text_on_cl("KhadashPay", 85);
  tft.setTextSize(1);
  disp_centered_text_on_cl("https://github.com/Northstrix/KhadashPay", 225);
}

void appr_cards_and_log_in(){
  operator_tft.fillScreen(0x0000);
  operator_tft.setTextColor(0xffff, 0x0000);
  operator_tft.setTextSize(1);
  operator_tft.setCursor(0,10);
  int act = 0;
  char card1[4];
  int card2[4];
  int card3[4];
  int card4[4];
  digitalWrite(26,HIGH);
  Serial.println("Approximate the RFID card N1 to the reader");
  operator_tft.print("Approximate RFID card N1  to the reader.");
  while (act < 90){
    bus2.tick();
    if (bus2.gotData()) {
      myStruct2 data;
      bus2.readData(data);
      if (act == 0){
        card1[0] = data.x[0];
        card1[1] = data.x[1];
        card1[2] = data.x[2];
        card1[3] = data.x[3];
        digitalWrite(26,LOW);
        delay(700);
        Serial.println("Approximate the RFID card N2 to the reader");
        digitalWrite(26,HIGH);
        operator_tft.setCursor(0,35);
        operator_tft.print("Approximate RFID card N2  to the reader.");
      }
      if (act == 1){
        card2[0] = int(data.x[0]);
        card2[1] = int(data.x[1]);
        card2[2] = int(data.x[2]);
        card2[3] = int(data.x[3]);
        digitalWrite(26,LOW);
        delay(700);
        Serial.println("Approximate the RFID card N3 to the reader");
        digitalWrite(26,HIGH);
        operator_tft.setCursor(0,60);
        operator_tft.println("Approximate RFID card N3  to the reader.");
      }
      if (act == 2){
        card3[0] = int(data.x[0]);
        card3[1] = int(data.x[1]);
        card3[2] = int(data.x[2]);
        card3[3] = int(data.x[3]);
        digitalWrite(26,LOW);
        delay(700);
        Serial.println("Approximate the RFID card N4 to the reader");
        digitalWrite(26,HIGH);
        operator_tft.setCursor(0,85);
        operator_tft.println("Approximate RFID card N4  to the reader.");
      }
      if (act == 3){
        card4[0] = int(data.x[0]);
        card4[1] = int(data.x[1]);
        card4[2] = int(data.x[2]);
        card4[3] = int(data.x[3]);
        act = 100;
      }
       act ++;
      }
  }
  digitalWrite(26,LOW);
  operator_tft.fillScreen(0x1557);
  operator_tft.fillRect(12, 12, 136, 94, 0x08c5);
  operator_tft.setTextColor(0x1557, 0x08c5);
  operator_tft.setTextSize(1);
  disp_centered_text_on_op("Unlock the device", 20);
  operator_tft.setTextColor(0xffff, 0x08c5);
  operator_tft.setTextSize(1);
  operator_tft.setCursor(21,55);
  operator_tft.print("Enter the password");
  operator_tft.drawLine(21, 64, 133, 64, 0xffff);
  disp_centered_text_on_op("Press Enter to log in", 92);
  operator_tft.setTextColor(0x08c5, 0x1557);
  operator_tft.setTextSize(1);
  operator_tft.setCursor(20,115);
  operator_tft.print("Password Length:0");
   
  pr_key = 0;
  String pass_lg;
  while (act < 900){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9){
          pass_lg += ch;
      }
      else if (ch == 127) { // Backspace
        
        if(pass_lg.length() > 0){ // Password
          pass_lg.remove(pass_lg.length() -1, 1);
          operator_tft.setTextColor(0xffff, 0x08c5);
          operator_tft.setTextSize(1);
          operator_tft.setCursor(21,55);
          operator_tft.print("                    ");
        }

          operator_tft.setTextColor(0x08c5, 0x1557);
          operator_tft.setTextSize(2);
          operator_tft.setCursor(116,115);
          operator_tft.print("   "); 

      }

      int inpl2 = pass_lg.length();
      if(inpl2 == 0){ // Password is empty
        operator_tft.setTextColor(0xffff, 0x08c5);
        operator_tft.setTextSize(1);
        operator_tft.setCursor(21,55);
        operator_tft.print("                    ");
        operator_tft.setCursor(21,55);
        operator_tft.print("Enter the password");
        operator_tft.setTextColor(0x08c5, 0x1557);
        operator_tft.setCursor(116,115);
        operator_tft.print("   ");
        operator_tft.setCursor(116,115);
        operator_tft.print("0"); 
      }
      else{
          operator_tft.setTextColor(0xffff, 0x08c5);
          operator_tft.setTextSize(1);
          operator_tft.setCursor(21,55);
          operator_tft.print("                    ");
          String stars = "";
          for(int i = 0; i < inpl2; i++){
            if (i < 19)
              stars += "*";
          }
          operator_tft.setTextColor(0xffff, 0x08c5);
          operator_tft.setTextSize(1);
          operator_tft.setCursor(21,55);
          operator_tft.print(stars);
          operator_tft.setTextColor(0x08c5, 0x1557);
          operator_tft.setCursor(116,115);
          operator_tft.print("   ");
          operator_tft.setCursor(116,115);
          operator_tft.print(inpl2);
      }
      if (pr_key == 13){
        keyb_inp = pass_lg;
        //Serial.println();
        //Serial.println(usrn_lg);
        //Serial.println(pass_lg);
        operator_tft.fillScreen(0x0000);
        operator_tft.setTextColor(0xffff, 0x0000);
        operator_tft.setTextSize(1);
        operator_tft.setCursor(0,5);
        operator_tft.print("Deriving keys.");
        operator_tft.setCursor(0,15);
        operator_tft.print("Please wait for a while.");
        modify_keys(card1, card2, card3, card4);
        act  = 1000;
      }
    }
 }
}

void main_menu(int curr_pos){
   operator_tft.fillRect(30, 30, 100, 68, 0xf17f);
   
   operator_tft.setTextColor(0xffff, 0xf17f);
   operator_tft.setTextSize(1);
   if (curr_pos == 0){
    operator_tft.fillRect(38, 38, 84, 12, 0xffff);
    operator_tft.setCursor(40,40);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("Make a sale");
    operator_tft.setTextColor(0xffff, 0xf17f);
    operator_tft.setCursor(40,52);
    operator_tft.print("Put money in");
    operator_tft.setCursor(40,64);
    operator_tft.print("New account");
    operator_tft.setCursor(40,76);
    operator_tft.print("View balance");
   }
   if (curr_pos == 1){
    operator_tft.setCursor(40,40);
    operator_tft.print("Make a sale");
    operator_tft.fillRect(38, 50, 84, 12, 0xffff);
    operator_tft.setCursor(40,52);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("Put money in");
    operator_tft.setCursor(40,64);
    operator_tft.setTextColor(0xffff, 0xf17f);
    operator_tft.print("New account");
    operator_tft.setCursor(40,76);
    operator_tft.print("View balance");
   }
   if (curr_pos == 2){
    operator_tft.setCursor(40,40);
    operator_tft.print("Make a sale");
    operator_tft.setCursor(40,52);
    operator_tft.print("Put money in");
    operator_tft.fillRect(38, 62, 84, 12, 0xffff);
    operator_tft.setCursor(40,64);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("New account");
    operator_tft.setTextColor(0xffff, 0xf17f);
    operator_tft.setCursor(40,76);
    operator_tft.print("View balance");
   }
   if (curr_pos == 3){
    operator_tft.setCursor(40,40);
    operator_tft.print("Make a sale");
    operator_tft.setCursor(40,52);
    operator_tft.print("Put money in");
    operator_tft.setCursor(40,64);
    operator_tft.print("New account");
    operator_tft.fillRect(38, 74, 84, 12, 0xffff);
    operator_tft.setCursor(40,76);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("View balance");
   }
   return;
}

void m_menu_rect(){
   operator_tft.fillScreen(0x1557);
   operator_tft.fillRect(15, 15, 130, 98, 0x08c5);
}

void create_accounts_table(){
   exeq_sql_statement("CREATE TABLE if not exists Accounts (Account_number TEXT, PIN TEXT, Balance TEXT);");
}

void exeq_sql_statement(char sql_statmnt[]){
   sqlite3 *db1;
   int rc;
   int str_len = dbase_name.length() + 1;
   char input_arr[str_len];
   dbase_name.toCharArray(input_arr, str_len);
   if (db_open(input_arr, &db1))
       return;

   rc = db_exec(db1, sql_statmnt);
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }

   sqlite3_close(db1);
}

void exeq_sql_statement_from_string(String squery){
   int squery_len = squery.length() + 1;
   char squery_array[squery_len];
   squery.toCharArray(squery_array, squery_len);
   exeq_sql_statement(squery_array);
   return;
}

size_t hex2bin_for_der (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)serp_key[i];
  }
  return 32;
}

bool verify_integrity(){
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;
  
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }

  return dec_tag.equals(res_hash);
}

void new_account() {
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  operator_tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x155b);
  operator_tft.setCursor(0, 5);
  operator_tft.setTextColor(0xffff, 0x3186);
  disp_centered_text_on_cl("Approximate the card to", 80);
  disp_centered_text_on_cl("the RFID reader", 100);
  operator_tft.print("Approximate the client's");
  operator_tft.setCursor(0, 15);
  operator_tft.print("card to the RFID reader.");
  operator_tft.setCursor(0, 115);
  operator_tft.print("Press Esc to cancel");
  digitalWrite(26, HIGH);
  char card1[4];
  byte mod_keys[3];
  String pin1;
  String pin2;
  bool try_again = false;
  bool canc = false;
  while (canc != true) {
    int act = 0;
    while (act < 90) {
      bus2.tick();
      if (bus2.gotData()) {
        myStruct2 data;
        bus2.readData(data);
        card1[0] = data.x[0];
        card1[1] = data.x[1];
        card1[2] = data.x[2];
        card1[3] = data.x[3];
        digitalWrite(26, LOW);
        delay(7);
        act = 100;
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          digitalWrite(26, LOW);
          break;
        }
      }
    }
    if (canc == true)
      break;
    digitalWrite(26, LOW);
    hmackey[0] = byte(card1[0]);
    key[0] = byte(card1[2]);
    serp_key[0] = byte(card1[3]);
    
    mod_keys[0] = byte(card1[0]);
    mod_keys[1] = byte(card1[2]);
    mod_keys[2] = byte(card1[3]);
    tft.fillScreen(0x155b);
    operator_tft.fillScreen(0x3186);
    operator_tft.setCursor(0, 5);
    operator_tft.print("Wait until client sets the");
    operator_tft.setCursor(0, 15);
    operator_tft.print("PIN");
    operator_tft.setCursor(0, 115);
    operator_tft.print("Press Esc to cancel");
    disp_centered_text_on_cl("Set your PIN", 60);
    disp_centered_text_on_cl("Remember that it can't", 80);
    disp_centered_text_on_cl("be changed!!!", 100);
    disp_centered_text_on_cl("* - Backspace", 190);
    disp_centered_text_on_cl("# - Enter", 210);
    tft.fillRect(102, 150, 116, 32, 0x08c5);
    tft.setCursor(112, 160);
    tft.setTextColor(0xffff, 0x08c5);
    bool setp1 = false;
    while (setp1 != true) {
      bus1.tick();
      if (bus1.gotData()) {
        myStruct data;
        bus1.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if (pr_key != '*' && pr_key != '#') {
          if (pin1.length() < 8)
            pin1 += ch;
        } else if (ch == '*') {
          if (pin1.length() > 0)
            pin1.remove(pin1.length() - 1, 1);
          tft.fillRect(102, 150, 116, 32, 0x08c5);
        }
        int inpl = pin1.length();

        tft.setCursor(112, 160);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < inpl; i++) {
          stars += "*";
        }
        tft.println(stars);
        if (pr_key == '#') {
          //Serial.println(pin1);
          setp1 = true;
        }
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          break;
        }
      }
    }
    if (canc == true)
      break;
    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text_on_cl("Enter your PIN again", 80);
    disp_centered_text_on_cl("* - Backspace", 190);
    disp_centered_text_on_cl("# - Enter", 210);
    tft.fillRect(102, 150, 116, 32, 0x08c5);
    tft.setCursor(112, 160);
    tft.setTextColor(0xffff, 0x08c5);
    bool setp2 = false;
    while (setp2 != true) {
      bus1.tick();
      if (bus1.gotData()) {
        myStruct data;
        bus1.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if (pr_key != '*' && pr_key != '#') {
          if (pin2.length() < 8)
            pin2 += ch;
        } else if (ch == '*') {
          if (pin2.length() > 0)
            pin2.remove(pin2.length() - 1, 1);
          tft.fillRect(102, 150, 116, 32, 0x08c5);
        }
        int inpl = pin2.length();

        tft.setCursor(112, 160);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < inpl; i++) {
          stars += "*";
        }
        tft.println(stars);
        if (pr_key == '#') {
          //Serial.println(pin2);
          setp2 = true;
        }
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          setp2 = true;
          break;
        }
      }
    }
    if (canc == true)
      break;
    if (canc == false) {
      if (pin1.equals(pin2)) {
        /*
        Serial.printf("\n%d %d %d %d\n", card1[0], card1[1], card1[2], card1[3]);
        Serial.println(pin1);
        Serial.println(pin2);
        */
        clb_m = 1;
        keyb_inp = "";
        dec_st = "";
        dec_tag = "";
        decract = 0;
        for(int i = 0; i < 4; i++)
          keyb_inp += card1[i];
        keyb_inp += pin1;
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        SHA256HMAC hmac(hmackey, sizeof(hmackey));
        hmac.doUpdate(keyb_inp_arr);
        byte authCode[SHA256HMAC_SIZE];
        hmac.doFinal(authCode);
        /*
        String res_hash;
        for (byte i=0; i < SHA256HMAC_SIZE; i++)
        {
            if (authCode[i]<0x10) { res_hash += 0; }{
              res_hash += String(authCode[i], HEX);
            }
        }
        */
        char hmacchar[32];
        for (int i = 0; i < 32; i++) {
          hmacchar[i] = char(authCode[i]);
        }
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_key();
          incr_second_key();
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight(hmacchar, p, 100, true, true);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p += 8;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
        String acc_num = HMAC_SHA256(dec_st);
        dec_st = "";
        dec_tag = "";
        decract = 0;
        String pin_to_store = encr_pin(pin1, card1, mod_keys);
        String balnc =  enc_balance(0.00, card1, mod_keys);
        /*
        Serial.println(acc_num);
        Serial.println(pin_to_store);
        Serial.println(balnc);
        */
        operator_tft.fillScreen(0x3186);
        operator_tft.setCursor(0,5);
        exeq_sql_statement_from_string("INSERT INTO Accounts (Account_number, PIN, Balance) VALUES( '" + acc_num + "','" + pin_to_store + "','" + balnc + "');");
        disp_inact_inscr();
        operator_tft.setTextSize(1);
        operator_tft.setCursor(0,105);
        operator_tft.print("                                                                                                    ");
        operator_tft.setCursor(0,105);
        operator_tft.print("Press any key to return tothe main menu");
        keyb_inp = "";
        while (!bus.gotData()){
          bus.tick();
        }
        canc = true;
      } else {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text_on_cl("PINs do not match.", 90);
        disp_centered_text_on_cl("Please try again.", 115);
        delay(3150);
        try_again = true;
        canc = true;
      }
    }
  }
  if (try_again == true)
    new_account();
  m_menu_rect();
  main_menu(cur_pos);
}

String encr_pin(String pin1, char card[], byte mod_keys[]){
  hmackey[0] = mod_keys[0];
  key[0] = mod_keys[1];
  serp_key[0] = mod_keys[2];
  keyb_inp = pin1;
  dec_st = "";
  dec_tag = "";
  decract = 0;
  int str_len = keyb_inp.length() + 1;
  char keyb_inp_arr[str_len];
  keyb_inp.toCharArray(keyb_inp_arr, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(keyb_inp_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  /*
  String res_hash;
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  */
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  int p = 0;
  for (int i = 0; i < 4; i++) {
    incr_key();
    incr_second_key();
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight(hmacchar, p, 100, true, true);
    p += 8;
  }
  p = 0;
  while (str_len > p + 1) {
    incr_Blwfsh_key();
    incr_key();
    incr_serp_key();
    incr_second_key();
    split_by_eight(keyb_inp_arr, p, str_len, true, true);
    p += 8;
  }
  rest_Blwfsh_k();
  rest_k();
  rest_serp_k();
  rest_s_k();
  String pin = HMAC_SHA256(dec_st);
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return pin;
}

String enc_balance(double blance, char card[], byte mod_keys[]){
  hmackey[0] = mod_keys[0];
  key[0] = mod_keys[1];
  serp_key[0] = mod_keys[2];
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
  //Serial.printf("\n%d %d %d\n", card[0], card[1], card[2]);
  for (int i = 0; i < 3; i++){
    if (int(card[i]) < 16)
      keyb_inp += "0";
    keyb_inp +=  String(int(card[i]), HEX);
  }
  keyb_inp += String(blance, decimal_spaces_in_balance);
  int str_len = keyb_inp.length() + 1;
  char keyb_inp_arr[str_len];
  keyb_inp.toCharArray(keyb_inp_arr, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(keyb_inp_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  /*
  String res_hash;
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  */
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  int p = 0;
  for (int i = 0; i < 4; i++) {
    incr_key();
    incr_second_key();
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight(hmacchar, p, 100, true, true);
    p += 8;
  }
  p = 0;
  while (str_len > p + 1) {
    incr_Blwfsh_key();
    incr_key();
    incr_serp_key();
    incr_second_key();
    split_by_eight(keyb_inp_arr, p, str_len, true, true);
    p += 8;
  }
  rest_Blwfsh_k();
  rest_k();
  rest_serp_k();
  rest_s_k();
  String encr_balance = dec_st;
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return encr_balance;
}

String HMAC_SHA256(String t_hash){
  int str_lentg = t_hash.length() + 1;
  char char_arraytg[str_lentg];
  t_hash.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;
  
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }

  return res_hash;
}

void c_balance(String ublc){
   tft.fillScreen(0x155b);
   tft.setTextColor(0xffff, 0x155b);
   tft.setTextSize(2);
   disp_centered_text_on_cl("Your balance is:", 50);
   tft.setTextSize(text_size_for_sale);
   disp_centered_text_on_cl(ublc + space_and_currency, 80);
   operator_tft.fillScreen(0x3186);
   operator_tft.setTextColor(0xdefb, 0x3186);
   operator_tft.setTextSize(1);
   disp_centered_text_on_op("Client's balance is",10);
   disp_centered_text_on_op(ublc + space_and_currency, 30);
   operator_tft.setCursor(0,92);
   operator_tft.print("Either press any key or wait until the client presses any key on the keypad to return to the main menu");
   tft.setTextSize(2);
   disp_centered_text_on_cl("Press any key to close", 190);
   disp_centered_text_on_cl("this window", 210);
}

void view_balance(){
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  operator_tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x155b);
  operator_tft.setCursor(0, 5);
  operator_tft.setTextColor(0xffff, 0x3186);
  disp_centered_text_on_cl("Approximate the card to", 80);
  disp_centered_text_on_cl("the RFID reader", 100);
  operator_tft.print("Approximate the client's");
  operator_tft.setCursor(0, 15);
  operator_tft.print("card to the RFID reader.");
  operator_tft.setCursor(0, 115);
  operator_tft.print("Press Esc to cancel");
  digitalWrite(26, HIGH);
  char card1[4];
  byte mod_keys[3];
  String pin1;
  String pin2;
  bool try_again = false;
  bool canc = false;
  while (canc != true) {
    int act = 0;
    while (act < 90) {
      bus2.tick();
      if (bus2.gotData()) {
        myStruct2 data;
        bus2.readData(data);
        card1[0] = data.x[0];
        card1[1] = data.x[1];
        card1[2] = data.x[2];
        card1[3] = data.x[3];
        digitalWrite(26, LOW);
        delay(7);
        act = 100;
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          digitalWrite(26, LOW);
          break;
        }
      }
    }
    if (canc == true)
      break;
    digitalWrite(26, LOW);
    hmackey[0] = byte(card1[0]);
    key[0] = byte(card1[2]);
    serp_key[0] = byte(card1[3]);
    
    mod_keys[0] = byte(card1[0]);
    mod_keys[1] = byte(card1[2]);
    mod_keys[2] = byte(card1[3]);
    tft.fillScreen(0x155b);
    operator_tft.fillScreen(0x3186);
    operator_tft.setCursor(0, 5);
    operator_tft.print("Wait until client enters");
    operator_tft.setCursor(0, 15);
    operator_tft.print("the PIN");
    operator_tft.setCursor(0, 115);
    operator_tft.print("Press Esc to cancel");

    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text_on_cl("Enter your PIN", 80);
    disp_centered_text_on_cl("* - Backspace", 190);
    disp_centered_text_on_cl("# - Enter", 210);
    tft.fillRect(102, 150, 116, 32, 0x08c5);
    tft.setCursor(112, 160);
    tft.setTextColor(0xffff, 0x08c5);
    bool setp2 = false;
    while (setp2 != true) {
      bus1.tick();
      if (bus1.gotData()) {
        myStruct data;
        bus1.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if (pr_key != '*' && pr_key != '#') {
          if (pin1.length() < 8)
            pin1 += ch;
        } else if (ch == '*') {
          if (pin1.length() > 0)
            pin1.remove(pin1.length() - 1, 1);
          tft.fillRect(102, 150, 116, 32, 0x08c5);
        }
        int inpl = pin1.length();

        tft.setCursor(112, 160);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < inpl; i++) {
          stars += "*";
        }
        tft.println(stars);
        if (pr_key == '#') {
          //Serial.println(pin2);
          setp2 = true;
        }
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          setp2 = true;
          break;
        }
      }
    }
    if (canc == true)
      break;
    if (canc == false) {
        /*
        Serial.printf("\n%d %d %d %d\n", card1[0], card1[1], card1[2], card1[3]);
        Serial.println(pin1);
        Serial.println(pin2);
        */
        clb_m = 1;
        keyb_inp = "";
        for(int i = 0; i < 4; i++)
          keyb_inp += card1[i];
        keyb_inp += pin1;
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        SHA256HMAC hmac(hmackey, sizeof(hmackey));
        hmac.doUpdate(keyb_inp_arr);
        byte authCode[SHA256HMAC_SIZE];
        hmac.doFinal(authCode);
        /*
        String res_hash;
        for (byte i=0; i < SHA256HMAC_SIZE; i++)
        {
            if (authCode[i]<0x10) { res_hash += 0; }{
              res_hash += String(authCode[i], HEX);
            }
        }
        */
        char hmacchar[32];
        for (int i = 0; i < 32; i++) {
          hmacchar[i] = char(authCode[i]);
        }
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_key();
          incr_second_key();
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight(hmacchar, p, 100, true, true);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p += 8;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
        String acc_num = HMAC_SHA256(dec_st);
        dec_st = "";
        dec_tag = "";
        decract = 0;
        String entered_pin = encr_pin(pin1, card1, mod_keys);
        //Serial.println(acc_num);
        //Serial.println(entered_pin);
        operator_tft.fillScreen(0x3186);
        operator_tft.setCursor(0,5);
        clb_m = 3;
        exeq_sql_statement_from_string("SELECT PIN FROM Accounts WHERE Account_number = '" + acc_num + "'");
        String extr_pin = dec_st;
        //Serial.println(extr_pin);
        dec_st = "";   dec_tag = "";   decract = 0;
        int eql = 1;
        for (int i = 0; i < 64; i++){
          if (entered_pin.charAt(i) == extr_pin.charAt(i))
            eql *= 1;
          else
            eql *= 0;
        }
        if (eql == 1){
          hmackey[0] = mod_keys[0];
          key[0] = mod_keys[1];
          serp_key[0] = mod_keys[2];
          clb_m = 2;
          exeq_sql_statement_from_string("SELECT Balance FROM Accounts WHERE Account_number = '" + acc_num + "'");
          bool pin_integrity = verify_integrity();
          if (pin_integrity == true){
            String extr_cardhex;
            for (int i = 0; i < 6; i++){
              extr_cardhex += dec_st.charAt(i);
            }
            String curr_cardhex;
            for (int i = 0; i < 3; i++){
              if (int(card1[i]) < 16)
                curr_cardhex += "0";
              curr_cardhex +=  String(int(card1[i]), HEX);
            }
            //Serial.println(extr_cardhex);
            //Serial.println(curr_cardhex);
            int eql1 = 1;
            for (int i = 0; i < 6; i++){
              if (extr_cardhex.charAt(i) == curr_cardhex.charAt(i))
                eql1 *= 1;
              else
                eql1 *= 0;
            }
            if (eql1 == 1){
              String usrsbln;
              for (int i = 0; i < dec_st.length(); i++){
                if (i > 5)
                  usrsbln += dec_st.charAt(i);
              }
              //Serial.println(usrsbln);
              String bal_t_d;
              for (int i = 0; i < usrsbln.length(); i++){
                if (usrsbln.charAt(i) > 31)
                  bal_t_d += usrsbln.charAt(i);
              }
              c_balance(bal_t_d);
              while (!bus.gotData()){
                bus.tick();
                bus1.tick();
                if (bus1.gotData())
                  break;
              }
            }
            else{
              //Serial.println("Integrity check failed");
              tft.setTextSize(2);
              tft.fillScreen(0xf961);
              tft.setTextColor(0xffff, 0xf961);
              disp_centered_text_on_cl("System error:", 90);
              disp_centered_text_on_cl("Integrity check failed", 110);
              operator_tft.setTextSize(1);
              operator_tft.fillScreen(0xf961);
              operator_tft.setTextColor(0xffff, 0xf961);
              disp_centered_text_on_op("System error:", 10);
              disp_centered_text_on_op("Integrity check failed", 30);
              delay(5000);
            }
          }
          else{
            //Serial.println("Integrity check failed");
            tft.setTextSize(2);
            tft.fillScreen(0xf961);
            tft.setTextColor(0xffff, 0xf961);
            disp_centered_text_on_cl("System error:", 90);
            disp_centered_text_on_cl("Integrity check failed", 110);
            operator_tft.setTextSize(1);
            operator_tft.fillScreen(0xf961);
            operator_tft.setTextColor(0xffff, 0xf961);
            disp_centered_text_on_op("System error:", 10);
            disp_centered_text_on_op("Integrity check failed", 30);
            delay(5000);
          }
        }
        else{
          //Serial.println("Wrong PIN");
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text_on_cl("Wrong PIN", 100);
          operator_tft.setTextSize(1);
          operator_tft.fillScreen(0xf961);
          operator_tft.setTextColor(0xffff, 0xf961);
          disp_centered_text_on_op("Wrong PIN", 10);
          delay(3150);
        }
        }
        keyb_inp = "";
        canc = true;
    }
  dec_st = "";   dec_tag = "";   decract = 0;
  disp_inact_inscr();
  m_menu_rect();
  main_menu(cur_pos);
}

void add_money(){
  keyb_inp = "";
  operator_tft.fillScreen(0x2145);
  operator_tft.setTextColor(0xe73c, 0x2145);
  operator_tft.setTextSize(1);
  operator_tft.setCursor(0,5);
  operator_tft.println("Enter the amount of money to add (in" + space_and_currency + "):");
  operator_tft.setCursor(0, 115);
  operator_tft.print("Press Esc to cancel");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && ((pr_key > 47 && pr_key < 58) || pr_key == 44 || pr_key == 46)){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        operator_tft.fillScreen(0x2145);
        operator_tft.setCursor(0,5);
        operator_tft.println("Enter the amount of money to add (in" + space_and_currency + "):");
        operator_tft.setCursor(0, 115);
        operator_tft.print("Press Esc to cancel");
      }
  int inpl = keyb_inp.length();
  operator_tft.setCursor(0,25);
  operator_tft.println(keyb_inp);
  if (pr_key == 13){
    keyb_inp.replace(",", ".");
    Serial.println(keyb_inp.toDouble());
    add_m(keyb_inp.toDouble());
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
     disp_inact_inscr();
     m_menu_rect();
     main_menu(cur_pos);
     return;
  }
  }
 }
}

void add_m(double amount_to_add){
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  operator_tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x155b);
  operator_tft.setCursor(0, 5);
  operator_tft.setTextColor(0xffff, 0x3186);
  disp_centered_text_on_cl("Put " + String(amount_to_add, decimal_spaces_in_balance) + space_and_currency + " in", 70);
  disp_centered_text_on_cl("Approximate the card to", 120);
  disp_centered_text_on_cl("the RFID reader", 140);
  operator_tft.print("Approximate the client's");
  operator_tft.setCursor(0, 15);
  operator_tft.print("card to the RFID reader.");
  operator_tft.setCursor(0, 115);
  operator_tft.print("Press Esc to cancel");
  digitalWrite(26, HIGH);
  char card1[4];
  byte mod_keys[3];
  String pin1;
  String pin2;
  bool try_again = false;
  bool canc = false;
  while (canc != true) {
    int act = 0;
    while (act < 90) {
      bus2.tick();
      if (bus2.gotData()) {
        myStruct2 data;
        bus2.readData(data);
        card1[0] = data.x[0];
        card1[1] = data.x[1];
        card1[2] = data.x[2];
        card1[3] = data.x[3];
        digitalWrite(26, LOW);
        delay(7);
        act = 100;
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          digitalWrite(26, LOW);
          break;
        }
      }
    }
    if (canc == true)
      break;
    digitalWrite(26, LOW);
    hmackey[0] = byte(card1[0]);
    key[0] = byte(card1[2]);
    serp_key[0] = byte(card1[3]);
    
    mod_keys[0] = byte(card1[0]);
    mod_keys[1] = byte(card1[2]);
    mod_keys[2] = byte(card1[3]);
    tft.fillScreen(0x155b);
    operator_tft.fillScreen(0x3186);
    operator_tft.setCursor(0, 5);
    operator_tft.print("Wait until client enters");
    operator_tft.setCursor(0, 15);
    operator_tft.print("the PIN");
    operator_tft.setCursor(0, 115);
    operator_tft.print("Press Esc to cancel");

    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text_on_cl("Enter your PIN", 80);
    disp_centered_text_on_cl("* - Backspace", 190);
    disp_centered_text_on_cl("# - Enter", 210);
    tft.fillRect(102, 150, 116, 32, 0x08c5);
    tft.setCursor(112, 160);
    tft.setTextColor(0xffff, 0x08c5);
    bool setp2 = false;
    while (setp2 != true) {
      bus1.tick();
      if (bus1.gotData()) {
        myStruct data;
        bus1.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if (pr_key != '*' && pr_key != '#') {
          if (pin1.length() < 8)
            pin1 += ch;
        } else if (ch == '*') {
          if (pin1.length() > 0)
            pin1.remove(pin1.length() - 1, 1);
          tft.fillRect(102, 150, 116, 32, 0x08c5);
        }
        int inpl = pin1.length();

        tft.setCursor(112, 160);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < inpl; i++) {
          stars += "*";
        }
        tft.println(stars);
        if (pr_key == '#') {
          //Serial.println(pin2);
          setp2 = true;
        }
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          setp2 = true;
          break;
        }
      }
    }
    if (canc == true)
      break;
    if (canc == false) {
        /*
        Serial.printf("\n%d %d %d %d\n", card1[0], card1[1], card1[2], card1[3]);
        Serial.println(pin1);
        Serial.println(pin2);
        */
        clb_m = 1;
        keyb_inp = "";
        for(int i = 0; i < 4; i++)
          keyb_inp += card1[i];
        keyb_inp += pin1;
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        SHA256HMAC hmac(hmackey, sizeof(hmackey));
        hmac.doUpdate(keyb_inp_arr);
        byte authCode[SHA256HMAC_SIZE];
        hmac.doFinal(authCode);
        /*
        String res_hash;
        for (byte i=0; i < SHA256HMAC_SIZE; i++)
        {
            if (authCode[i]<0x10) { res_hash += 0; }{
              res_hash += String(authCode[i], HEX);
            }
        }
        */
        char hmacchar[32];
        for (int i = 0; i < 32; i++) {
          hmacchar[i] = char(authCode[i]);
        }
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_key();
          incr_second_key();
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight(hmacchar, p, 100, true, true);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p += 8;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
        String acc_num = HMAC_SHA256(dec_st);
        dec_st = "";
        dec_tag = "";
        decract = 0;
        String entered_pin = encr_pin(pin1, card1, mod_keys);
        //Serial.println(acc_num);
        //Serial.println(entered_pin);
        operator_tft.fillScreen(0x3186);
        operator_tft.setCursor(0,5);
        clb_m = 3;
        exeq_sql_statement_from_string("SELECT PIN FROM Accounts WHERE Account_number = '" + acc_num + "'");
        String extr_pin = dec_st;
        //Serial.println(extr_pin);
        dec_st = "";   dec_tag = "";   decract = 0;
        int eql = 1;
        for (int i = 0; i < 64; i++){
          if (entered_pin.charAt(i) == extr_pin.charAt(i))
            eql *= 1;
          else
            eql *= 0;
        }
        if (eql == 1){
          hmackey[0] = mod_keys[0];
          key[0] = mod_keys[1];
          serp_key[0] = mod_keys[2];
          clb_m = 2;
          exeq_sql_statement_from_string("SELECT Balance FROM Accounts WHERE Account_number = '" + acc_num + "'");
          bool pin_integrity = verify_integrity();
          if (pin_integrity == true){
            String extr_cardhex;
            for (int i = 0; i < 6; i++){
              extr_cardhex += dec_st.charAt(i);
            }
            String curr_cardhex;
            for (int i = 0; i < 3; i++){
              if (int(card1[i]) < 16)
                curr_cardhex += "0";
              curr_cardhex +=  String(int(card1[i]), HEX);
            }
            //Serial.println(extr_cardhex);
            //Serial.println(curr_cardhex);
            int eql1 = 1;
            for (int i = 0; i < 6; i++){
              if (extr_cardhex.charAt(i) == curr_cardhex.charAt(i))
                eql1 *= 1;
              else
                eql1 *= 0;
            }
            if (eql1 == 1){
              String usrsbln;
              for (int i = 0; i < dec_st.length(); i++){
                if (i > 5)
                  usrsbln += dec_st.charAt(i);
              }
              //Serial.println(usrsbln);
              String bal_t_d;
              for (int i = 0; i < usrsbln.length(); i++){
                if (usrsbln.charAt(i) > 31)
                  bal_t_d += usrsbln.charAt(i);
              }
              double new_blnc = bal_t_d.toDouble() + amount_to_add;
              String nbalnc = enc_balance(new_blnc, card1, mod_keys);
              clb_m = 1;
              exeq_sql_statement_from_string("UPDATE Accounts set Balance = '" + nbalnc + "' where Account_number = '" + acc_num + "';");
              operator_tft.setCursor(0, 115);
              operator_tft.print("Press Esc to cancel");
              disp_inact_inscr();
              while (!bus.gotData()){
                bus.tick();
                bus1.tick();
                if (bus1.gotData())
                  break;
              }
            }
            else{
              //Serial.println("Integrity check failed");
              tft.setTextSize(2);
              tft.fillScreen(0xf961);
              tft.setTextColor(0xffff, 0xf961);
              disp_centered_text_on_cl("System error:", 90);
              disp_centered_text_on_cl("Integrity check failed", 110);
              operator_tft.setTextSize(1);
              operator_tft.fillScreen(0xf961);
              operator_tft.setTextColor(0xffff, 0xf961);
              disp_centered_text_on_op("System error:", 10);
              disp_centered_text_on_op("Integrity check failed", 30);
              delay(5000);
            }
          }
          else{
            //Serial.println("Integrity check failed");
            tft.setTextSize(2);
            tft.fillScreen(0xf961);
            tft.setTextColor(0xffff, 0xf961);
            disp_centered_text_on_cl("System error:", 90);
            disp_centered_text_on_cl("Integrity check failed", 110);
            operator_tft.setTextSize(1);
            operator_tft.fillScreen(0xf961);
            operator_tft.setTextColor(0xffff, 0xf961);
            disp_centered_text_on_op("System error:", 10);
            disp_centered_text_on_op("Integrity check failed", 30);
            delay(5000);
          }
        }
        else{
          //Serial.println("Wrong PIN");
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text_on_cl("Wrong PIN", 100);
          operator_tft.setTextSize(1);
          operator_tft.fillScreen(0xf961);
          operator_tft.setTextColor(0xffff, 0xf961);
          disp_centered_text_on_op("Wrong PIN", 10);
          delay(3150);
        }
        }
        keyb_inp = "";
        canc = true;
    }
  dec_st = "";   dec_tag = "";   decract = 0;
  disp_inact_inscr();
  m_menu_rect();
  main_menu(cur_pos);
  return;
}

void spend_money(){
  keyb_inp = "";
  operator_tft.fillScreen(0x2145);
  operator_tft.setTextColor(0xe73c, 0x2145);
  operator_tft.setTextSize(1);
  operator_tft.setCursor(0,5);
  operator_tft.println("Enter the price (in" + space_and_currency + "):");
  operator_tft.setCursor(0, 115);
  operator_tft.print("Press Esc to cancel");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && ((pr_key > 47 && pr_key < 58) || pr_key == 44 || pr_key == 46)){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        operator_tft.fillScreen(0x2145);
        operator_tft.setCursor(0,5);
        operator_tft.println("Enter the price (in" + space_and_currency + "):");
        operator_tft.setCursor(0, 115);
        operator_tft.print("Press Esc to cancel");
      }
  int inpl = keyb_inp.length();
  operator_tft.setCursor(0,25);
  operator_tft.println(keyb_inp);
  if (pr_key == 13){
    keyb_inp.replace(",", ".");
    Serial.println(keyb_inp.toDouble());
    spnd_m(keyb_inp.toDouble());
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
     disp_inact_inscr();
     m_menu_rect();
     main_menu(cur_pos);
     return;
  }
  }
 }
}

void spnd_m(double amount_to_spend){
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  operator_tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x155b);
  operator_tft.setCursor(0, 5);
  operator_tft.setTextColor(0xffff, 0x3186);
  disp_centered_text_on_cl("Sale", 30);
  tft.setTextSize(text_size_for_sale);
  disp_centered_text_on_cl(String(amount_to_spend, decimal_spaces_in_balance) + space_and_currency, 60);
  tft.setTextSize(2);
  disp_centered_text_on_cl("Approximate the card to", 100);
  disp_centered_text_on_cl("the RFID reader", 120);
  operator_tft.print("Approximate the client's");
  operator_tft.setCursor(0, 15);
  operator_tft.print("card to the RFID reader.");
  operator_tft.setCursor(0, 115);
  operator_tft.print("Press Esc to cancel");
  digitalWrite(26, HIGH);
  char card1[4];
  byte mod_keys[3];
  String pin1;
  String pin2;
  bool try_again = false;
  bool canc = false;
  while (canc != true) {
    int act = 0;
    while (act < 90) {
      bus2.tick();
      if (bus2.gotData()) {
        myStruct2 data;
        bus2.readData(data);
        card1[0] = data.x[0];
        card1[1] = data.x[1];
        card1[2] = data.x[2];
        card1[3] = data.x[3];
        digitalWrite(26, LOW);
        delay(7);
        act = 100;
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          digitalWrite(26, LOW);
          break;
        }
      }
    }
    if (canc == true)
      break;
    digitalWrite(26, LOW);
    hmackey[0] = byte(card1[0]);
    key[0] = byte(card1[2]);
    serp_key[0] = byte(card1[3]);
    
    mod_keys[0] = byte(card1[0]);
    mod_keys[1] = byte(card1[2]);
    mod_keys[2] = byte(card1[3]);
    tft.fillScreen(0x155b);
    operator_tft.fillScreen(0x3186);
    operator_tft.setCursor(0, 5);
    operator_tft.print("Wait until client enters");
    operator_tft.setCursor(0, 15);
    operator_tft.print("the PIN");
    operator_tft.setCursor(0, 115);
    operator_tft.print("Press Esc to cancel");

    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text_on_cl("Enter your PIN", 80);
    disp_centered_text_on_cl("* - Backspace", 190);
    disp_centered_text_on_cl("# - Enter", 210);
    tft.fillRect(102, 150, 116, 32, 0x08c5);
    tft.setCursor(112, 160);
    tft.setTextColor(0xffff, 0x08c5);
    bool setp2 = false;
    while (setp2 != true) {
      bus1.tick();
      if (bus1.gotData()) {
        myStruct data;
        bus1.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if (pr_key != '*' && pr_key != '#') {
          if (pin1.length() < 8)
            pin1 += ch;
        } else if (ch == '*') {
          if (pin1.length() > 0)
            pin1.remove(pin1.length() - 1, 1);
          tft.fillRect(102, 150, 116, 32, 0x08c5);
        }
        int inpl = pin1.length();

        tft.setCursor(112, 160);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < inpl; i++) {
          stars += "*";
        }
        tft.println(stars);
        if (pr_key == '#') {
          //Serial.println(pin2);
          setp2 = true;
        }
      }
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        if (int(ch) == 27) {
          canc = true;
          setp2 = true;
          break;
        }
      }
    }
    if (canc == true)
      break;
    if (canc == false) {
        /*
        Serial.printf("\n%d %d %d %d\n", card1[0], card1[1], card1[2], card1[3]);
        Serial.println(pin1);
        Serial.println(pin2);
        */
        clb_m = 1;
        keyb_inp = "";
        for(int i = 0; i < 4; i++)
          keyb_inp += card1[i];
        keyb_inp += pin1;
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        SHA256HMAC hmac(hmackey, sizeof(hmackey));
        hmac.doUpdate(keyb_inp_arr);
        byte authCode[SHA256HMAC_SIZE];
        hmac.doFinal(authCode);
        /*
        String res_hash;
        for (byte i=0; i < SHA256HMAC_SIZE; i++)
        {
            if (authCode[i]<0x10) { res_hash += 0; }{
              res_hash += String(authCode[i], HEX);
            }
        }
        */
        char hmacchar[32];
        for (int i = 0; i < 32; i++) {
          hmacchar[i] = char(authCode[i]);
        }
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_key();
          incr_second_key();
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight(hmacchar, p, 100, true, true);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p += 8;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
        String acc_num = HMAC_SHA256(dec_st);
        dec_st = "";
        dec_tag = "";
        decract = 0;
        String entered_pin = encr_pin(pin1, card1, mod_keys);
        //Serial.println(acc_num);
        //Serial.println(entered_pin);
        operator_tft.fillScreen(0x3186);
        operator_tft.setCursor(0,5);
        clb_m = 3;
        exeq_sql_statement_from_string("SELECT PIN FROM Accounts WHERE Account_number = '" + acc_num + "'");
        String extr_pin = dec_st;
        //Serial.println(extr_pin);
        dec_st = "";   dec_tag = "";   decract = 0;
        int eql = 1;
        for (int i = 0; i < 64; i++){
          if (entered_pin.charAt(i) == extr_pin.charAt(i))
            eql *= 1;
          else
            eql *= 0;
        }
        if (eql == 1){
          hmackey[0] = mod_keys[0];
          key[0] = mod_keys[1];
          serp_key[0] = mod_keys[2];
          clb_m = 2;
          exeq_sql_statement_from_string("SELECT Balance FROM Accounts WHERE Account_number = '" + acc_num + "'");
          bool pin_integrity = verify_integrity();
          if (pin_integrity == true){
            String extr_cardhex;
            for (int i = 0; i < 6; i++){
              extr_cardhex += dec_st.charAt(i);
            }
            String curr_cardhex;
            for (int i = 0; i < 3; i++){
              if (int(card1[i]) < 16)
                curr_cardhex += "0";
              curr_cardhex +=  String(int(card1[i]), HEX);
            }
            //Serial.println(extr_cardhex);
            //Serial.println(curr_cardhex);
            int eql1 = 1;
            for (int i = 0; i < 6; i++){
              if (extr_cardhex.charAt(i) == curr_cardhex.charAt(i))
                eql1 *= 1;
              else
                eql1 *= 0;
            }
            if (eql1 == 1){
              String usrsbln;
              for (int i = 0; i < dec_st.length(); i++){
                if (i > 5)
                  usrsbln += dec_st.charAt(i);
              }
              //Serial.println(usrsbln);
              String bal_t_d;
              for (int i = 0; i < usrsbln.length(); i++){
                if (usrsbln.charAt(i) > 31)
                  bal_t_d += usrsbln.charAt(i);
              }
              double new_blnc = bal_t_d.toDouble() - amount_to_spend;
              if (new_blnc >= 0){
                String nbalnc = enc_balance(new_blnc, card1, mod_keys);
                clb_m = 1;
                exeq_sql_statement_from_string("UPDATE Accounts set Balance = '" + nbalnc + "' where Account_number = '" + acc_num + "';");
                operator_tft.setCursor(0, 115);
                operator_tft.print("Press Esc to cancel");
                disp_inact_inscr();
                while (!bus.gotData()){
                  bus.tick();
                  bus1.tick();
                  if (bus1.gotData())
                    break;
                }
              }
              else{
                tft.setTextSize(2);
                tft.fillScreen(0xf17f);
                tft.setTextColor(0xffff, 0xf17f);
                disp_centered_text_on_cl("Not enough money in the", 90);
                disp_centered_text_on_cl("account to complete the", 110);
                disp_centered_text_on_cl("transaction", 130);
                operator_tft.setTextSize(1);
                operator_tft.fillScreen(0xf17f);
                operator_tft.setTextColor(0xffff, 0xf17f);
                disp_centered_text_on_op("Not enough money in the   client's account to       complete the transaction", 5);
                delay(7000);
              }
            }
            else{
              //Serial.println("Integrity check failed");
              tft.setTextSize(2);
              tft.fillScreen(0xf961);
              tft.setTextColor(0xffff, 0xf961);
              disp_centered_text_on_cl("System error:", 90);
              disp_centered_text_on_cl("Integrity check failed", 110);
              operator_tft.setTextSize(1);
              operator_tft.fillScreen(0xf961);
              operator_tft.setTextColor(0xffff, 0xf961);
              disp_centered_text_on_op("System error:", 10);
              disp_centered_text_on_op("Integrity check failed", 30);
              delay(5000);
            }
          }
          else{
            //Serial.println("Integrity check failed");
            tft.setTextSize(2);
            tft.fillScreen(0xf961);
            tft.setTextColor(0xffff, 0xf961);
            disp_centered_text_on_cl("System error:", 90);
            disp_centered_text_on_cl("Integrity check failed", 110);
            operator_tft.setTextSize(1);
            operator_tft.fillScreen(0xf961);
            operator_tft.setTextColor(0xffff, 0xf961);
            disp_centered_text_on_op("System error:", 10);
            disp_centered_text_on_op("Integrity check failed", 30);
            delay(5000);
          }
        }
        else{
          //Serial.println("Wrong PIN");
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text_on_cl("Wrong PIN", 100);
          operator_tft.setTextSize(1);
          operator_tft.fillScreen(0xf961);
          operator_tft.setTextColor(0xffff, 0xf961);
          disp_centered_text_on_op("Wrong PIN", 10);
          delay(3150);
        }
        }
        keyb_inp = "";
        canc = true;
    }
  dec_st = "";   dec_tag = "";   decract = 0;
  disp_inact_inscr();
  m_menu_rect();
  main_menu(cur_pos);
  return;
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  mySerial1.begin(9600);
  mySerial2.begin(9600);
  pinMode(26, OUTPUT);
  digitalWrite(26,LOW);
  m = 2; // Set AES to 256 bit
  cur_pos = 0;
  tft.begin(); 
  tft.setRotation(0);
  operator_tft.initR(INITR_BLACKTAB);
  operator_tft.setRotation(1);
    if (SPIFFS.begin(true)) {
  }
  else{
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  // list SPIFFS contents
  File root = SPIFFS.open("/");
  if (!root) {
      Serial.println("- failed to open directory");
      return;
  }
  if (!root.isDirectory()) {
      Serial.println(" - not a directory");
      return;
  }
  /*
  File file = root.openNextFile();
  while (file) {
      if (file.isDirectory()) {
          Serial.print("  DIR : ");
          Serial.println(file.name());
      } else {
          Serial.print("  FILE: ");
          Serial.print(file.name());
          Serial.print("\tSIZE: ");
          Serial.println(file.size());
      }
      file = root.openNextFile();
  }
  */
   sqlite3_initialize();
   tft.setTextSize(2);
   tft.setRotation(1);
   tft.fillScreen(0x155b);
   tft.setTextColor(0xffff, 0x155b);
   disp_centered_text_on_cl("Waiting for operator", 120);
   disp_centered_text_on_cl("to log in", 145);
   tft.setTextSize(4);
   disp_centered_text_on_cl("KhadashPay", 50);
   tft.setTextSize(1);
   disp_centered_text_on_cl("https://github.com/Northstrix/KhadashPay", 225);
   appr_cards_and_log_in();
}

void loop() {
  char emptyar[2];
  byte emptyauthCode[SHA256HMAC_SIZE];
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(emptyar);
  hmac.doFinal(emptyauthCode);
  back_k();
  back_s_k();
  back_serp_k();
  back_Blwfsh_k();
  bus.tick();
  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    //Serial.println(ch);
    //Serial.println(int(ch));
    pr_key = int(ch);
    if (pr_key == 10)
      cur_pos++;
      
    if (pr_key == 11)
      cur_pos--;
      
    if (cur_pos < 0)
      cur_pos = 3;
      
    if (cur_pos > 3)
      cur_pos = 0;

    if (cur_pos == 0 && pr_key == 13) // Make a sale
      spend_money();
    if (cur_pos == 1 && pr_key == 13) // Put money in
      add_money();
    if (cur_pos == 2 && pr_key == 13) // New account
      new_account();
    if (cur_pos == 3 && pr_key == 13) // View balance
      view_balance();

    main_menu(cur_pos);
  } 
}
