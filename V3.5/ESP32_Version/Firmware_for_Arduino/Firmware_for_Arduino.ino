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
#include <stdint.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <ps2dev.h>
#include <Keypad.h>

const byte ROWS = 4; //four rows
const byte COLS = 4; //four columns
char keys[ROWS][COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};
byte rowPins[ROWS] = {11, 10, 9, 8}; //connect to the row pinouts of the keypad
byte colPins[COLS] = {7, 6, 5, 4}; //connect to the column pinouts of the keypad


Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

PS2dev keyboard(3, 2); //clock, data

void setup() {
  //Serial.begin(115200);
  keyboard.keyboard_init();
}

void loop() {
  char key = keypad.getKey();
  if (key == '0') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::ZERO);
  }
  if (key == '1') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::ONE);
  }
  if (key == '2') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::TWO);
  }
  if (key == '3') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::THREE);
  }
  if (key == '4') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::FOUR);
  }
  if (key == '5') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::FIVE);
  }
  if (key == '6') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::SIX);
  }
  if (key == '7') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::SEVEN);
  }
  if (key == '8') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::EIGHT);
  }
  if (key == '9') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::NINE);
  }
  if (key == 'A') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::PERIOD);
  }
  if (key == 'B') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_press(PS2dev::LEFT_SHIFT);
    keyboard.keyboard_mkbrk(PS2dev::B);
    keyboard.keyboard_release(PS2dev::LEFT_SHIFT);
  }
  if (key == 'C') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::ESCAPE);
  }
  if (key == 'D') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_press(PS2dev::LEFT_SHIFT);
    keyboard.keyboard_mkbrk(PS2dev::D);
    keyboard.keyboard_release(PS2dev::LEFT_SHIFT);
  }
  if (key == '*') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::BACKSPACE);
  }
  if (key == '#') {
    unsigned char leds;
    if (keyboard.keyboard_handle( & leds)) {}
    keyboard.keyboard_mkbrk(PS2dev::ENTER);
  }
  delay(1);
}
