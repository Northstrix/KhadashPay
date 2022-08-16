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
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ST7735.h>
#define TFT_CS1         5
#define TFT_RST1        19
#define TFT_DC1         22
Adafruit_ST7735 operator_tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

void main_menu(int curr_pos){
   operator_tft.fillRect(30, 30, 100, 68, 0xf17f);
   
   operator_tft.setTextColor(0xffff, 0xf17f);
   operator_tft.setTextSize(1);
   if (curr_pos == 0){
    operator_tft.fillRect(38, 38, 84, 12, 0xffff);
    operator_tft.setCursor(40,40);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("Spend money");
    operator_tft.setTextColor(0xffff, 0xf17f);
    operator_tft.setCursor(40,52);
    operator_tft.print("Add money");
    operator_tft.setCursor(40,64);
    operator_tft.print("New account");
    operator_tft.setCursor(40,76);
    operator_tft.print("View balance");
   }
   if (curr_pos == 1){
    operator_tft.setCursor(40,40);
    operator_tft.print("Spend money");
    operator_tft.fillRect(38, 50, 84, 12, 0xffff);
    operator_tft.setCursor(40,52);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("Add money");
    operator_tft.setCursor(40,64);
    operator_tft.setTextColor(0xffff, 0xf17f);
    operator_tft.print("New account");
    operator_tft.setCursor(40,76);
    operator_tft.print("View balance");
   }
   if (curr_pos == 2){
    operator_tft.setCursor(40,40);
    operator_tft.print("Spend money");
    operator_tft.setCursor(40,52);
    operator_tft.print("Add money");
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
    operator_tft.print("Spend money");
    operator_tft.setCursor(40,52);
    operator_tft.print("Add money");
    operator_tft.setCursor(40,64);
    operator_tft.print("New account");
    operator_tft.fillRect(38, 74, 84, 12, 0xffff);
    operator_tft.setCursor(40,76);
    operator_tft.setTextColor(0xf17f, 0xffff);
    operator_tft.print("View balance");
   }
}

void setup() {
   operator_tft.initR(INITR_BLACKTAB);
   operator_tft.setRotation(1);
   operator_tft.fillScreen(0x1557);
   operator_tft.fillRect(15, 15, 130, 98, 0x08c5);
}

void loop(){
  for (int i = 0; i < 4; i++){
    main_menu(i);
    delay(1000);
  }
}
