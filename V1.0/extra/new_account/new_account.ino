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
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);


void disp_centered_text_on_cl(String t_disp, int y){
   int16_t x1, y1;
   uint16_t w, h;
   tft.getTextBounds(t_disp, 320, 0, &x1, &y1, &w, &h);
   tft.setCursor(160 - (w / 2), y);
   tft.print(t_disp);
}

void new_account(){
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff, 0x155b);
  disp_centered_text_on_cl("Approximate the card to", 80);
  disp_centered_text_on_cl("the RFID reader", 100);
  delay(5000);
  tft.fillScreen(0x155b);
  disp_centered_text_on_cl("Set your PIN", 60);
  disp_centered_text_on_cl("Remember that it can't", 80);
  disp_centered_text_on_cl("be changed!!!", 100);
  disp_centered_text_on_cl("* - Backspace", 190);
  disp_centered_text_on_cl("# - Enter", 210);
  tft.fillRect(102, 150, 116, 32, 0x08c5);
  tft.setCursor(112, 160);
  tft.setTextColor(0xffff, 0x08c5);
  for(int i = 0; i < 8; i++){
   tft.print("*");
   delay(750);
  }
  delay(5000);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff, 0x155b);
  disp_centered_text_on_cl("Enter your PIN again", 80);
  disp_centered_text_on_cl("* - Backspace", 190);
  disp_centered_text_on_cl("# - Enter", 210);
  tft.fillRect(102, 150, 116, 32, 0x08c5);
  tft.setCursor(112, 160);
  tft.setTextColor(0xffff, 0x08c5);
  for(int i = 0; i < 8; i++){
   tft.print("*");
   delay(750);
  }
}

void setup() {
   tft.begin(); 
   tft.setRotation(1);
   new_account();
}
void loop(){
  
}
