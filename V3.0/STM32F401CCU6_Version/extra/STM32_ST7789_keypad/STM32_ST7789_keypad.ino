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
https://github.com/intrbiz/arduino-crypto
https://github.com/adafruit/SdFat
https://github.com/miguelbalboa/rfid
https://github.com/Chris--A/Keypad
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit-ST7735-Library
*/
#include <Adafruit_GFX.h>    // Core graphics library
#include <Adafruit_ST7789.h> // Hardware-specific library for ST7789
#include <SPI.h>

#define TFT_CS PB10
#define TFT_RST PB2
#define TFT_DC PB1

#define TFT_MOSI PA1  // Data out
#define TFT_SCLK PA0  // Clock out

Adafruit_ST7789 tft = Adafruit_ST7789(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);

#include <Keypad.h>
#define ROW_NUM     4
#define COLUMN_NUM  4

char p_k[ROW_NUM][COLUMN_NUM] = {
  {'1', '2', '3', '.'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};

uint16_t c;
String keyboard_input;
int curr_key;
const uint16_t current_inact_clr = 0x051b;
bool finish_input;
bool act;

byte rowPins[ROW_NUM] = {PB9, PB8, PB7, PB6}; 
byte colPins[COLUMN_NUM] = {PB5, PB4, PB3, PA15}; 
Keypad keypad = Keypad( makeKeymap(p_k), rowPins, colPins, ROW_NUM, COLUMN_NUM );

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  tft.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  tft.setCursor((320 - width) / 2, h);
  tft.print(text);
}

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 24);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");
}

void change_char() {
  if (keyboard_input.length() > 0)
    curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(keyboard_input);
}

void disp_stars() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

void encdr_and_keyb_input() {
  finish_input = false;
  while (finish_input == false) {

   char key = keypad.getKey();
    if (key) {
      
    if (key == '*') {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      tft.fillRect(0, 48, 312, 62, 0x0000);
      //Serial.println(keyboard_input);
      change_char();
      disp();
    }

    else if (key == 'C'){
      act = false;
      finish_input = true;
    }

    else if (key == '#'){
      finish_input = true;
    }

    else{
      keyboard_input += char(key);
        change_char();
        disp();
    }
    
   }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  while (finish_input == false) {

   char key = keypad.getKey();
    if (key) {
      
    if (key == '*') {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      tft.fillRect(0, 48, 312, 62, 0x0000);
      //Serial.println(keyboard_input);
      change_char();
      disp_stars();
    }

    else if (key == '#'){
      finish_input = true;
    }

    else{
      keyboard_input += char(key);
        change_char();
        disp_stars();
    }
    
   }
    delayMicroseconds(400);
  }
}

void setup() {
  Serial.begin(115200);
  tft.init(240, 320);
  tft.invertDisplay(false);
  //tft.fillScreen(0x0000);
  tft.setRotation(1);
}

void loop() {
  act = true;
  //clear_variables();
  keyboard_input = "";
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter string:");
  encdr_and_keyb_input();
  //star_encdr_and_keyb_input();
  if (act == true) {
    Serial.println("Continue");
    Serial.println(keyboard_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.print("Contnue with \"");
    tft.print(keyboard_input);
    tft.print("\"");
    delay(2500);
  }
  else{
    Serial.println("Cancel");
    Serial.println(keyboard_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.print("Cancel (input) \"");
    tft.print(keyboard_input);
    tft.print("\"");
    delay(2500);
  }
}
