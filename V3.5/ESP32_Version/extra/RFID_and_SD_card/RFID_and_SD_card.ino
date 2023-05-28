/*
KhadashPay
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/khadashpay/
https://osdn.net/projects/khadashpay/
https://github.com/Northstrix/KhadashPay
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/miguelbalboa/rfid
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/Chris--A/Keypad
https://github.com/Harvie/ps2dev
*/
#include <SPI.h>
#include <MFRC522.h>
#include "FS.h"
#include "SD.h"
#include "SPI.h"

#define SS_PIN  21
#define RST_PIN 1

MFRC522 rfid(SS_PIN, RST_PIN);

void enable_sd(){
  digitalWrite(1, LOW);
  digitalWrite(25, HIGH);
}

void enable_rfid_reader(){
  digitalWrite(1, HIGH);
  digitalWrite(25, LOW);
}

void write_to_file_with_overwrite(fs::FS &fs, String filename, String content) {
   //Serial.printf("Writing file: %s\r\n", filename);

   File file = fs.open(filename, FILE_WRITE);
   if(!file){
      //Serial.println("− failed to open file for writing");
      return;
   }
   if(file.print(content)){
      //Serial.println("− file written");
   }else {
      //Serial.println("− frite failed");
   }
}

String read_file(fs::FS &fs, String filename) {
  String file_content;
   //Serial.printf("Reading file: %s\r\n", filename);

   File file = fs.open(filename);
   if(!file || file.isDirectory()){
       //Serial.println("− failed to open file for reading");
       return "-1";
   }

   //Serial.println("− read from file:");
   while(file.available()){
      file_content += char(file.read());
   }
   return file_content;
}

void delete_file(fs::FS &fs, String filename){
   //Serial.printf("Deleting file: %s\r\n", filename);
   if(fs.remove(filename)){
      //Serial.println("− file deleted");
   } else {
      //Serial.println("− delete failed");
   }
}

void setup() {
  Serial.begin(115200);
  //enable_rfid_reader();
  SPI.begin(); // init SPI bus
  rfid.PCD_Init(); // init MFRC522

  //enable_sd();

  Serial.println("Tap an RFID/NFC tag on the RFID-RC522 reader");
  if(!SD.begin(5)){
    Serial.println("Card Mount Failed");
  }
  else{
    Serial.println("SD Card Initialized Successfully");
  }

  write_to_file_with_overwrite(SD, "/test", "1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./");
  Serial.println(read_file(SD, "/test"));
  delete_file(SD, "/test");
  
  //enable_rfid_reader();
}

void loop() {
  if (rfid.PICC_IsNewCardPresent()) { // new tag is available
    if (rfid.PICC_ReadCardSerial()) { // NUID has been readed
      MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
      Serial.print("RFID/NFC Tag Type: ");
      Serial.println(rfid.PICC_GetTypeName(piccType));

      // print UID in Serial Monitor in the hex format
      Serial.print("UID:");
      for (int i = 0; i < rfid.uid.size; i++) {
        Serial.print(rfid.uid.uidByte[i] < 0x10 ? " 0" : " ");
        Serial.print(rfid.uid.uidByte[i], HEX);
      }
      Serial.println();

      rfid.PICC_HaltA(); // halt PICC
      rfid.PCD_StopCrypto1(); // stop encryption on PCD
    }
  }
}
