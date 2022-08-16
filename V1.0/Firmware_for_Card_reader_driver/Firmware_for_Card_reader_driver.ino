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
#include <SPI.h>
#include <MFRC522.h>
#include <SoftwareSerial.h>
SoftwareSerial mySerial(5, 4);
#include "GBUS.h"
GBUS bus(&mySerial, 7, 16);
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);

struct myStruct {
  char x[4];
};
void setup() 
{
  //Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
  //Serial.println("Approximate four cards to the reader...");
  mySerial.begin(9600);
}
void loop() 
{
    if ( ! mfrc522.PICC_IsNewCardPresent()) 
    {
      return;
    }
    if ( ! mfrc522.PICC_ReadCardSerial()) 
    {
      return;
    }
      //Serial.println(mfrc522.uid.uidByte[i]);
      myStruct data;
      data.x[0] = (char) int(mfrc522.uid.uidByte[0]);
      data.x[1] = (char) int(mfrc522.uid.uidByte[1]);
      data.x[2] = (char) int(mfrc522.uid.uidByte[2]);
      data.x[3] = (char) int(mfrc522.uid.uidByte[3]);
      bus.sendData(5, data);
      delay(700);
    //Serial.println();
}
