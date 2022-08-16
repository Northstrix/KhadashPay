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

String space_and_currency = " BTC";
int text_size_for_sale = 3;

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
   disp_centered_text_on_op("User's balance is",10);
   disp_centered_text_on_op(ublc + space_and_currency, 30);
   operator_tft.setCursor(0,92);
   operator_tft.print("Either press any key or wait until the client presses any key on the keypad to return to the main menu");
   tft.setTextSize(2);
   disp_centered_text_on_cl("Press any key to close", 190);
   disp_centered_text_on_cl("this window", 210);
}

void setup() {
   tft.begin(); 
   tft.setRotation(1);
   operator_tft.initR(INITR_BLACKTAB);
   operator_tft.setRotation(1);
   c_balance("0.0000000001");
}
void loop(){
  
}
