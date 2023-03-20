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
https://github.com/Chris--A/Keypad
*/
// !!! Before uploading this sketch -
// Switch the partition scheme to the
// "No OTA (2MB APP/2MB SPIFFS)" !!!
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "khadashpaypictures.h"
#include "sha512.h"
#include <TFT_eSPI.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>

#define ROW_NUM 4
#define COLUMN_NUM 4

TFT_eSPI tft = TFT_eSPI();
TFT_eSprite mvng_bc = TFT_eSprite( & tft);

/*
 * RFID Reader - ESP32
 * SDA - D21
 * SCK - D18
 * MOSI - D23
 * MISO - D19
 * RST - D27
 */

#define SS_PIN 21
#define RST_PIN 25

MFRC522 rfid(SS_PIN, RST_PIN);

byte read_cards[16];

DES des;
Blowfish blowfish;

char p_k[ROW_NUM][COLUMN_NUM] = {
  {'1', '2', '3', '.'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};

byte pin_rows[ROW_NUM]      = {27, 26, 33, 32};
byte pin_column[COLUMN_NUM] = {16, 17, 5, 22};

Keypad keypad = Keypad(makeKeymap(p_k), pin_rows, pin_column, ROW_NUM, COLUMN_NUM);

uint16_t code;

int m;
int clb_m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
uint16_t c;
String keypad_input;
int curr_key;
bool finish_input;
bool act;
bool decrypt_tag;
const uint16_t current_inact_clr = 0x051b;
const uint16_t five_six_five_red_color = 0xf940;
bool cont_t_nxt;
int menu_pos;
bool gen_r;
String space_and_currency = " USD"; // Space + Currency name
int text_size_for_sale = 3;

// Keys (Below)
String kderalgs = "qO9l3h7R3K2YmS1b8498NDaBpDS4s6Vh4t3D";
int numofkincr = 638;
byte hmackey[] = {"mVVak9H0795Joh1g3Jfsv804gh9E4a92XH281HgO45efDS7UZ4OV9xA140CT7JaYd7R879lJyyH8AlQcB7nBa24cAry466q8c5I1936URr9Sm"};
byte des_key[] = {
0x96,0x29,0xf1,0xc0,0xdb,0xde,0xef,0x39,
0x3c,0xf6,0xfe,0x0a,0xd9,0xf9,0xa3,0x28,
0x47,0xe1,0x48,0xc6,0xf0,0xa8,0x3e,0xe2
};
uint8_t AES_key[32] = {
0x5f,0x11,0x6f,0xe8,
0x6a,0x43,0xff,0x25,
0xa9,0x8b,0x25,0xbc,
0xda,0xd7,0x49,0xf3,
0x53,0xcd,0x5f,0x6c,
0x6c,0x30,0x5d,0xf6,
0x6f,0xaa,0xcf,0xbc,
0xa6,0x8d,0x6a,0x46
};
unsigned char Blwfsh_key[] = {
0xde,0xe6,0xd6,0xcb,
0x1e,0x58,0x3d,0xfa,
0xdb,0xbd,0xba,0xba,
0x65,0x64,0xfa,0x0a,
0xe2,0x6a,0x8d,0xf3,
0x1c,0xfc,0x0a,0xda
};
uint8_t serp_key[32] = {
0xdd,0x4e,0xd5,0x8b,
0xe8,0x0e,0xfb,0xfe,
0xb6,0x0d,0xec,0xbf,
0x8a,0x8a,0x5c,0xf0,
0xfe,0xef,0xbd,0xcc,
0x43,0x61,0x6e,0x5e,
0x00,0x3e,0xd0,0x3d,
0xf9,0xda,0x37,0xb8
};
uint8_t second_AES_key[32] = {
0xff,0xd4,0x03,0xda,
0xe5,0xdc,0xc7,0xa6,
0xb7,0xfa,0x49,0x84,
0xcb,0x30,0xb3,0x8b,
0xcf,0x61,0xef,0x68,
0xda,0xe5,0x56,0x57,
0x50,0x08,0x82,0xb1,
0x1d,0x7f,0x8c,0x9f
};
// Keys (Above)

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];
uint8_t back_s_AES_key[32];
uint8_t back_def_serp_key[32];

void back_def_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_def_serp_key[i] = serp_key[i];
  }
}

void rest_def_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_def_serp_key[i];
  }
}

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_Bl_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void back_3des_k() {
  for (int i = 0; i < 24; i++) {
    back_des_key[i] = des_key[i];
  }
}

void rest_3des_k() {
  for (int i = 0; i < 24; i++) {
    des_key[i] = back_des_key[i];
  }
}

void back_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    back_s_AES_key[i] = second_AES_key[i];
  }
}

void rest_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    second_AES_key[i] = back_s_AES_key[i];
  }
}

void incr_des_key() {
  if (des_key[7] == 255) {
    des_key[7] = 0;
    if (des_key[6] == 255) {
      des_key[6] = 0;
      if (des_key[5] == 255) {
        des_key[5] = 0;
        if (des_key[4] == 255) {
          des_key[4] = 0;
          if (des_key[3] == 255) {
            des_key[3] = 0;
            if (des_key[2] == 255) {
              des_key[2] = 0;
              if (des_key[1] == 255) {
                des_key[1] = 0;
                if (des_key[0] == 255) {
                  des_key[0] = 0;
                } else {
                  des_key[0]++;
                }
              } else {
                des_key[1]++;
              }
            } else {
              des_key[2]++;
            }
          } else {
            des_key[3]++;
          }
        } else {
          des_key[4]++;
        }
      } else {
        des_key[5]++;
      }
    } else {
      des_key[6]++;
    }
  } else {
    des_key[7]++;
  }

  if (des_key[15] == 255) {
    des_key[15] = 0;
    if (des_key[14] == 255) {
      des_key[14] = 0;
      if (des_key[13] == 255) {
        des_key[13] = 0;
        if (des_key[12] == 255) {
          des_key[12] = 0;
          if (des_key[11] == 255) {
            des_key[11] = 0;
            if (des_key[10] == 255) {
              des_key[10] = 0;
              if (des_key[9] == 255) {
                des_key[9] = 0;
                if (des_key[8] == 255) {
                  des_key[8] = 0;
                } else {
                  des_key[8]++;
                }
              } else {
                des_key[9]++;
              }
            } else {
              des_key[10]++;
            }
          } else {
            des_key[11]++;
          }
        } else {
          des_key[12]++;
        }
      } else {
        des_key[13]++;
      }
    } else {
      des_key[14]++;
    }
  } else {
    des_key[15]++;
  }

  if (des_key[23] == 255) {
    des_key[23] = 0;
    if (des_key[22] == 255) {
      des_key[22] = 0;
      if (des_key[21] == 255) {
        des_key[21] = 0;
        if (des_key[20] == 255) {
          des_key[20] = 0;
          if (des_key[19] == 255) {
            des_key[19] = 0;
            if (des_key[18] == 255) {
              des_key[18] = 0;
              if (des_key[17] == 255) {
                des_key[17] = 0;
                if (des_key[16] == 255) {
                  des_key[16] = 0;
                } else {
                  des_key[16]++;
                }
              } else {
                des_key[17]++;
              }
            } else {
              des_key[18]++;
            }
          } else {
            des_key[19]++;
          }
        } else {
          des_key[20]++;
        }
      } else {
        des_key[21]++;
      }
    } else {
      des_key[22]++;
    }
  } else {
    des_key[23]++;
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
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

void incr_second_AES_key() {
  if (second_AES_key[0] == 255) {
    second_AES_key[0] = 0;
    if (second_AES_key[1] == 255) {
      second_AES_key[1] = 0;
      if (second_AES_key[2] == 255) {
        second_AES_key[2] = 0;
        if (second_AES_key[3] == 255) {
          second_AES_key[3] = 0;
          if (second_AES_key[4] == 255) {
            second_AES_key[4] = 0;
            if (second_AES_key[5] == 255) {
              second_AES_key[5] = 0;
              if (second_AES_key[6] == 255) {
                second_AES_key[6] = 0;
                if (second_AES_key[7] == 255) {
                  second_AES_key[7] = 0;
                  if (second_AES_key[8] == 255) {
                    second_AES_key[8] = 0;
                    if (second_AES_key[9] == 255) {
                      second_AES_key[9] = 0;
                      if (second_AES_key[10] == 255) {
                        second_AES_key[10] = 0;
                        if (second_AES_key[11] == 255) {
                          second_AES_key[11] = 0;
                          if (second_AES_key[12] == 255) {
                            second_AES_key[12] = 0;
                            if (second_AES_key[13] == 255) {
                              second_AES_key[13] = 0;
                              if (second_AES_key[14] == 255) {
                                second_AES_key[14] = 0;
                                if (second_AES_key[15] == 255) {
                                  second_AES_key[15] = 0;
                                } else {
                                  second_AES_key[15]++;
                                }
                              } else {
                                second_AES_key[14]++;
                              }
                            } else {
                              second_AES_key[13]++;
                            }
                          } else {
                            second_AES_key[12]++;
                          }
                        } else {
                          second_AES_key[11]++;
                        }
                      } else {
                        second_AES_key[10]++;
                      }
                    } else {
                      second_AES_key[9]++;
                    }
                  } else {
                    second_AES_key[8]++;
                  }
                } else {
                  second_AES_key[7]++;
                }
              } else {
                second_AES_key[6]++;
              }
            } else {
              second_AES_key[5]++;
            }
          } else {
            second_AES_key[4]++;
          }
        } else {
          second_AES_key[3]++;
        }
      } else {
        second_AES_key[2]++;
      }
    } else {
      second_AES_key[1]++;
    }
  } else {
    second_AES_key[0]++;
  }
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_3des_k();
  back_AES_k();
  back_Bl_k();
  back_serp_k();
  back_second_AES_key();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
  rest_second_AES_key();
}

void clear_variables() {
  keypad_input = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return;
}

int get_rnd_val() {
  if (gen_r == true)
    return esp_random() % 256;
  else
    return AES_key[1];
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below)

void split_by_ten(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 2; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp() {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 10; i++) {
    array_for_CBC_mode[i] = get_rnd_val();
  }

  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {

  for (int i = 2; i < 8; i++) {
    res2[i] = get_rnd_val();
  }

  byte out[8];
  byte out2[8];
  des.tripleEncrypt(out, res, des_key);
  incr_des_key();
  des.tripleEncrypt(out2, res2, des_key);
  incr_des_key();

  char t_aes[16];

  for (int i = 0; i < 8; i++) {
    int b = out[i];
    t_aes[i] = char(b);
  }

  for (int i = 0; i < 8; i++) {
    int b = out2[i];
    t_aes[i + 8] = char(b);
  }

  encrypt_with_AES(t_aes);
}

void encrypt_with_AES(char t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t AES_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  unsigned char first_eight[8];
  unsigned char second_eight[8];
  for (int i = 0; i < 8; i++) {
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i + 8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  encrypt_with_serpent();
}

void encrypt_with_Blowfish(unsigned char inp[], bool lrside) {
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  String encrypted_with_blowfish;
  for (int i = 0; i < 8; i++) {
    if (lrside == false)
      pass_to_serp[i] = int(plt[i]);
    if (lrside == true)
      pass_to_serp[i + 8] = int(plt[i]);
  }
  incr_Blwfsh_key();
}

void encrypt_with_serpent() {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
      if (decract > 0) {
        if (i < 10) {
          array_for_CBC_mode[i] = byte(int(ct2.b[i]));
        }
      }
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte prev_res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }

  if (br == false) {
    if (decract > 10) {
      for (int i = 0; i < 10; i++) {
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    unsigned char lh[8];
    unsigned char rh[8];
    for (int i = 0; i < 8; i++) {
      lh[i] = (unsigned char) int(ct2.b[i]);
      rh[i] = (unsigned char) int(ct2.b[i + 8]);
    }
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(lh, lh, sizeof(lh));
    incr_Blwfsh_key();
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(rh, rh, sizeof(rh));
    incr_Blwfsh_key();
    uint8_t ret_text[16] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    };
    uint8_t cipher_text[16] = {
      0
    };
    for (int i = 0; i < 8; i++) {
      int c = int(lh[i]);
      cipher_text[i] = c;
    }
    for (int i = 0; i < 8; i++) {
      int c = int(rh[i]);
      cipher_text[i + 8] = c;
    }
    /*
    for (int i=0; i<16; i++) {
      if(cipher_text[i]<16)
        Serial.print("0");
      Serial.print(cipher_text[i],HEX);
    }
    Serial.println();
    */
    uint32_t AES_key_bit[3] = {
      128,
      192,
      256
    };
    aes_context ctx;
    aes_set_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();

    byte res[8];
    byte res2[8];

    for (int i = 0; i < 8; i++) {
      res[i] = int(ret_text[i]);
      res2[i] = int(ret_text[i + 8]);
    }

    byte out[8];
    byte out2[8];
    des.tripleDecrypt(out, res, des_key);
    incr_des_key();
    des.tripleDecrypt(out2, res2, des_key);
    incr_des_key();
    /*
        Serial.println();
        for (int i=0; i<8; i++) {
          if(out[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }

        for (int i=0; i<8; i++) {
          if(out2[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }
        Serial.println();
    */

    if (decract > 2) {
      for (int i = 0; i < 8; i++) {
        out[i] ^= array_for_CBC_mode[i];
      }

      for (int i = 0; i < 2; i++) {
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false) {

        for (i = 0; i < 8; ++i) {
          if (out[i] > 0)
            dec_st += char(out[i]);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] > 0)
            dec_st += char(out2[i]);
        }

      } else {
        for (i = 0; i < 8; ++i) {
          if (out[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out[i], HEX);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out2[i], HEX);
        }
      }
    }

    if (decract == -1) {
      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i] = out[i];
      }

      for (i = 0; i < 2; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encrypt_hash_with_tdes_aes_blf_srp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  for (int i = 0; i < 3; i++) {
    split_by_ten(hmacchar, p, 100);
    p += 10;
  }
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encrypt_hash_with_tdes_aes_blf_srp(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i += 32) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();

  back_keys();
  dec_st = "";
  decrypt_tag = false;
  int ct_len1 = ct.length() + 1;
  char ct_array1[ct_len1];
  ct.toCharArray(ct_array1, ct_len1);
  ext = 128;
  decract = -1;
  while (ct_len1 > ext) {
    split_for_decryption(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE - 2; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  /*
  Serial.println(dec_st);
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
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
  if (keypad_input.length() > 0)
    curr_key = keypad_input.charAt(keypad_input.length() - 1);
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
  tft.print(keypad_input);
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
  int plnt = keypad_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

void get_keypad_input() {
  finish_input = false;
  while (finish_input == false) {

    char key = keypad.getKey();
    if (key) {

      if (key == '*') {
        if (keypad_input.length() > 0)
          keypad_input.remove(keypad_input.length() - 1, 1);
        tft.fillRect(0, 48, 312, 192, 0x0000);
        //Serial.println(keypad_input);
        change_char();
        disp();
      } else if (key == 'C') {
        act = false;
        finish_input = true;
      } else if (key == '#') {
        finish_input = true;
      } else {
        keypad_input += char(key);
        change_char();
        disp();
      }

    }
    delayMicroseconds(400);
  }
}

void star_get_keypad_input() {
  finish_input = false;
  while (finish_input == false) {

    char key = keypad.getKey();
    if (key) {

      if (key == '*') {
        if (keypad_input.length() > 0)
          keypad_input.remove(keypad_input.length() - 1, 1);
        //Serial.println(keypad_input);
        tft.fillRect(0, 48, 312, 192, 0x0000);
        //Serial.println(keypad_input);
        change_char();
        disp_stars();
      } else if (key == '#') {
        finish_input = true;
      } else {
        keypad_input += char(key);
        change_char();
        disp_stars();
      }

    }
    delayMicroseconds(400);
  }
}

// Functions that work with files in LittleFS (Below)

void write_to_file_with_overwrite(fs::FS & fs, String filename, String content) {
  //Serial.printf("Writing file: %s\r\n", filename);

  File file = fs.open(filename, FILE_WRITE);
  if (!file) {
    //Serial.println("− failed to open file for writing");
    return;
  }
  if (file.print(content)) {
    //Serial.println("− file written");
  } else {
    //Serial.println("− frite failed");
  }
}

String read_file(fs::FS & fs, String filename) {
  String file_content;
  //Serial.printf("Reading file: %s\r\n", filename);

  File file = fs.open(filename);
  if (!file || file.isDirectory()) {
    //Serial.println("− failed to open file for reading");
    return "-1";
  }

  //Serial.println("− read from file:");
  while (file.available()) {
    file_content += char(file.read());
  }
  return file_content;
}

void delete_file(fs::FS & fs, String filename) {
  //Serial.printf("Deleting file: %s\r\n", filename);
  if (fs.remove(filename)) {
    //Serial.println("− file deleted");
  } else {
    //Serial.println("− delete failed");
  }
}

// Functions that work with files in LittleFS (Above)

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    char key = keypad.getKey();
    if (key) {
      break_the_loop = true;
    }
    delayMicroseconds(400);
  }
}

void continue_to_unlock() {
  if (read_file(SPIFFS, "/kppass").equals("-1"))
    set_pass();
  else
    unlock_khadashpay();
  return;
}

void set_pass() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Set Master Password");
  get_keypad_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Master Password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keypad_input);
  String bck = keypad_input;
  modify_keys();
  keypad_input = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Master Password Set", 65);
  disp_centered_text("Successfully", 85);
  disp_centered_text("Press any key", 105);
  disp_centered_text("to continue", 125);
  press_any_key_to_continue();
  call_main_menu();
  return;
}

void set_psswd() {
  int str_len = keypad_input.length() + 1;
  char input_arr[str_len];
  keypad_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);
  back_keys();
  dec_st = "";
  encrypt_hash_with_tdes_aes_blf_srp(h);
  rest_keys();
  //Serial.println(dec_st);

  write_to_file_with_overwrite(SPIFFS, "/kppass", dec_st);
  String opcard;
  for (int i = 0; i < 4; i++) {
    if (read_cards[i] < 16)
      opcard += "0";
    opcard += String(read_cards[i], HEX);
  }
  back_keys();
  dec_st = "";
  encrypt_hash_with_tdes_aes_blf_srp(opcard);
  rest_keys();
  //Serial.println(dec_st);
  write_to_file_with_overwrite(SPIFFS, "/oprcrd", dec_st);
}

void modify_keys() {
  keypad_input += kderalgs;
  int str_len = keypad_input.length() + 1;
  char input_arr[str_len];
  keypad_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == numofkincr / 2) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
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
  for (int i = 0; i < 13; i++) {
    hmackey[i] = res[i];
  }
  des_key[9] = res[13];
  des_key[16] = (unsigned char) res[31];
  des_key[17] = (unsigned char) res[32];
  des_key[18] = (unsigned char) res[33];
  serp_key[12] = int(res[34]);
  serp_key[14] = int(res[35]);
  for (int i = 0; i < 9; i++) {
    Blwfsh_key[i] = (unsigned char) res[i + 14];
  }
  for (int i = 0; i < 3; i++) {
    des_key[i] = (unsigned char) res[i + 23];
  }
  for (int i = 0; i < 5; i++) {
    hmackey[i + 13] = int(res[i + 26]);
  }
  for (int i = 0; i < 10; i++) {
    AES_key[i] = int(res[i + 36]);
  }
  for (int i = 0; i < 9; i++) {
    serp_key[i] = int(res[i + 46]);
  }
  for (int i = 0; i < 4; i++) {
    hmackey[i + 18] = res[i + 55];
    des_key[i + 3] = (unsigned char) res[i + 59];
  }
  for (int i = 0; i < 5; i++) {
    second_AES_key[i] = ((int(res[i + 31]) * int(res[i + 11])) + int(res[50])) % 256;
  }
}

void unlock_khadashpay() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  set_stuff_for_input("Enter Master Password");
  star_get_keypad_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  disp_centered_text("Unlocking", 45);
  disp_centered_text("KhadashPay", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keypad_input);
  String bck = keypad_input;
  modify_keys();
  keypad_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  if (next_act == true) {
    tft.setTextSize(2);
    disp_centered_text("KhadashPay", 45);
    disp_centered_text("unlocked", 65);
    disp_centered_text("successfully", 85);
    disp_centered_text("Press any key", 105);
    disp_centered_text("to continue", 125);
    press_any_key_to_continue();
    call_main_menu();
    return;
  } else {
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", 65);
    tft.setTextColor(0xffff);
    disp_centered_text("Please reboot", 100);
    disp_centered_text("the device", 120);
    disp_centered_text("and try again", 140);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  int str_len = keypad_input.length() + 1;
  char input_arr[str_len];
  keypad_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);

  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int h_len1 = h.length() + 1;
  char h_arr[h_len1];
  h.toCharArray(h_arr, h_len1);
  hmac.doUpdate(h_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  String res_hash;
  for (int i = 0; i < 30; i++) {
    if (hmacchar[i] < 0x10)
      res_hash += "0";
    res_hash += String(hmacchar[i], HEX);
  }
  /*
    Serial.println();

      for (int i = 0; i < 30; i++) {
        if (hmacchar[i] < 16)
          Serial.print("0");
        Serial.print(hmacchar[i], HEX);
      }
    Serial.println();
  */
  back_keys();
  clear_variables();
  //Serial.println(read_file(SPIFFS, "/kppass"));
  decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/kppass"));
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

void disp_centered_text(String text, int h) {
  if (text.length() < 27)
    tft.drawCentreString(text, 160, h, 1);
  else {
    tft.setCursor(0, h);
    tft.println(text);
  }
}

int chosen_lock_screen;
unsigned int k;

void display_letters_with_shifting_background() {

  if (chosen_lock_screen == 0) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Dallas[(i + 4 + k) % 320][j + 89]);
      }
    }
    mvng_bc.pushSprite(4, 89, TFT_TRANSPARENT);
  }

  if (chosen_lock_screen == 1) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Tel_Aviv[(i + 4 + k) % 320][j + 120]);
      }
    }
    mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
  }

  if (chosen_lock_screen == 2) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Montreal[(i + 4 + k) % 320][j + 89]);
      }
    }
    mvng_bc.pushSprite(4, 89, TFT_TRANSPARENT);
  }

  if (chosen_lock_screen == 3) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Austin[(i + 4 + k) % 320][j + 122]);
      }
    }
    mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
  }

  if (chosen_lock_screen == 4) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, San_Francisco[(i + 4 + k) % 320][j + 98]);
      }
    }
    mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
  }

  if (chosen_lock_screen == 5) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Minneapolis[(i + 4 + k) % 320][j + 89]);
      }
    }
    mvng_bc.pushSprite(4, 89, TFT_TRANSPARENT);
  }
  k++;
}

void display_lock_screen() {
  if (chosen_lock_screen == 0) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Dallas[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 1) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Tel_Aviv[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Montreal[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 3) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Austin[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 4) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, San_Francisco[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 5) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Minneapolis[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 0 || chosen_lock_screen == 2 || chosen_lock_screen == 5) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_per[i][j] == 1)
          tft.drawPixel(i + 4, j + 89, 0xf7de);
      }
    }
  } else {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_per[i][j] == 1)
          tft.drawPixel(i + 4, j + 10, 0xf7de);
      }
    }
  }
}

void lock_scr_with_rfid() {
  chosen_lock_screen = esp_random() % 6;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Tap RFID card N1", 205);
  bool break_rfid_loop = false;
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  k = 0;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        read_cards[0] = rfid.uid.uidByte[0];
        read_cards[1] = rfid.uid.uidByte[1];
        read_cards[2] = rfid.uid.uidByte[2];
        read_cards[3] = rfid.uid.uidByte[3];
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    display_letters_with_shifting_background();
  }
  int new_screen = chosen_lock_screen;
  while (chosen_lock_screen == new_screen) {
    new_screen = esp_random() % 6;
  }
  chosen_lock_screen = new_screen;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Tap RFID card N2", 205);
  break_rfid_loop = false;
  k = 0;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        read_cards[4] = rfid.uid.uidByte[0];
        read_cards[5] = rfid.uid.uidByte[1];
        read_cards[6] = rfid.uid.uidByte[2];
        read_cards[7] = rfid.uid.uidByte[3];
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    display_letters_with_shifting_background();
  }
  new_screen = chosen_lock_screen;
  while (chosen_lock_screen == new_screen) {
    new_screen = esp_random() % 6;
  }
  chosen_lock_screen = new_screen;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Tap RFID card N3", 205);
  break_rfid_loop = false;
  k = 0;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        read_cards[8] = rfid.uid.uidByte[0];
        read_cards[9] = rfid.uid.uidByte[1];
        read_cards[10] = rfid.uid.uidByte[2];
        read_cards[11] = rfid.uid.uidByte[3];
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    display_letters_with_shifting_background();
  }
  new_screen = chosen_lock_screen;
  while (chosen_lock_screen == new_screen) {
    new_screen = esp_random() % 6;
  }
  chosen_lock_screen = new_screen;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Tap RFID card N4", 205);
  break_rfid_loop = false;
  k = 0;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        read_cards[12] = rfid.uid.uidByte[0];
        read_cards[13] = rfid.uid.uidByte[1];
        read_cards[14] = rfid.uid.uidByte[2];
        read_cards[15] = rfid.uid.uidByte[3];
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    display_letters_with_shifting_background();
  }
  //mvng_bc.deleteSprite();
}

// Menu (Below)
void call_main_menu() {
  tft.fillScreen(0x0000);
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_per[i][j] == 1 || khadash_pay_icon[i][j] == 1)
        tft.drawPixel(i + 4, j + 10, 0xf7de);
    }
  }
  disp_menu();
}

void disp_menu() {
  tft.setTextSize(2);
  if (menu_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Make A Sale", 100);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
  }
  if (menu_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    tft.setTextColor(0xffff);
    disp_centered_text("Put Money In", 120);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
  }
  if (menu_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    tft.setTextColor(0xffff);
    disp_centered_text("New Account", 140);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Balance", 160);
  }
  if (menu_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    tft.setTextColor(0xffff);
    disp_centered_text("View Balance", 160);
  }
}
void lock_screen_keypad() {
  chosen_lock_screen = esp_random() % 6;
  display_lock_screen();
  tft.setTextSize(1);
  tft.setTextColor(0xf7de);
  tft.drawCentreString("github.com/Northstrix/KhadashPay", 160, 230, 1);
  bool break_loop = false;
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  k = 0;
  while (break_loop == false) {
    char key = keypad.getKey();
    if (key) {
      break_loop = true;
    }
    display_letters_with_shifting_background();
  }
  call_main_menu();
  //mvng_bc.deleteSprite();
}
// Menu (Above)

void press_key_on_keypad() {
  bool break_loop = false;
  while (break_loop == false) {
    char key = keypad.getKey();
    if (key) {

      if (key == '#') {
        cont_t_nxt = true;
        break_loop = true;
      }

      if (key == 'C') {
        cont_t_nxt = false;
        break_loop = true;
      }

    }
  }
}

void approximate_operator_card_to_continue(byte cps) {
  // KhadashPay requires the operator card in order to encrypt/decrypt user data
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Approximate", 45);
  disp_centered_text("Operator Card", 65);
  disp_centered_text("To The RFID", 85);
  disp_centered_text("Card Reader", 105);
  disp_centered_text("Press 'C' To Cancel", 220);
  String read_card;
  bool cont_to_next_step = true;
  bool break_rfid_loop = false;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        for (int i = 0; i < 4; i++) {
          if (rfid.uid.uidByte[i] < 16)
            read_card += "0";
          read_card += String(rfid.uid.uidByte[i], HEX);
        }
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    char key = keypad.getKey();
    if (key) {
      if (key == 'C') {
        cont_to_next_step = false;
        break_rfid_loop = true;
      }
    }
  }
  if (cont_to_next_step == true) {
    clear_variables();
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    int str_len = read_card.length() + 1;
    char read_card_arr[str_len];
    read_card.toCharArray(read_card_arr, str_len);
    hmac.doUpdate(read_card_arr);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    String hashed_card;
    for (int i = 0; i < 30; i++) {
      if (authCode[i] < 16)
        hashed_card += "0";
      hashed_card += String(authCode[i], HEX);
    }
    back_keys();
    clear_variables();
    //Serial.println(read_file(SPIFFS, "/oprcrd"));
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/oprcrd"));
    //Serial.println(dec_tag);
    //Serial.println(hashed_card);
    for (int i = 10; i < 28; i++) {
      serp_key[i] = authCode[i];
    }
    if (dec_tag.equals(hashed_card) && cps > 1) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press '#'", 45);
      disp_centered_text("And Give The Device", 65);
      disp_centered_text("To The Client", 85);
      disp_centered_text("Press 'C' to Cancel", 220);
      cont_t_nxt = false;
      press_key_on_keypad();
      if (cont_t_nxt == true) {
        if (cps == 2)
          create_new_account();
        if (cps == 3)
          view_account_balance();
      }
    }
    else if (dec_tag.equals(hashed_card) && cps < 2) {
      if (cps == 0)
        reduce_account_balance();
      if (cps == 1)
        add_money_to_account();
    }
    else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Wrong Operator Card!", 45);
      tft.setTextColor(0xffff);
      disp_centered_text("Please reboot", 80);
      disp_centered_text("the device", 100);
      disp_centered_text("and try again", 120);
      for (;;)
        delay(1000);
    }
  } else {

  }
  call_main_menu();
}

void create_new_account() {
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff);
  disp_centered_text("Approximate the card to", 90);
  disp_centered_text("the RFID reader", 110);
  disp_centered_text("Press 'C' to Cancel", 220);
  bool cont_to_next_step = true;
  bool break_rfid_loop = false;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        read_cards[0] = rfid.uid.uidByte[0];
        read_cards[1] = rfid.uid.uidByte[1];
        read_cards[2] = rfid.uid.uidByte[2];
        read_cards[3] = rfid.uid.uidByte[3];
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    char key = keypad.getKey();
    if (key) {
      if (key == 'C') {
        cont_to_next_step = false;
        break_rfid_loop = true;
      }
    }
  }
  if (cont_to_next_step == true) {
    for (int i = 0; i < 4; i++) {
      serp_key[i + 28] = read_cards[i];
    }
    tft.fillScreen(0x155b);
    disp_centered_text("Set your PIN", 60);
    disp_centered_text("Remember that it can't", 80);
    disp_centered_text("be changed!!!", 100);
    disp_centered_text("* - Backspace", 180);
    disp_centered_text("# - Enter", 200);
    disp_centered_text("C - Cancel", 220);
    tft.fillRect(102, 135, 116, 32, 0x08c5);
    tft.setCursor(112, 145);
    tft.setTextColor(0xffff, 0x08c5);
    cont_t_nxt = false;
    bool setp1 = false;
    String pin1;
    String pin2;
    while (setp1 != true) {
      char key = keypad.getKey();
      if (key) {

        if (key == '#') {
          cont_t_nxt = true;
          setp1 = true;
        } else if (key == 'C') {
          cont_t_nxt = false;
          setp1 = true;
        } else if (key == '*') {
          pin1.remove(pin1.length() - 1, 1);
          tft.fillRect(102, 135, 116, 32, 0x08c5);
        } else {
          if (pin1.length() < 8)
            pin1 += key;
        }
        tft.setCursor(112, 140);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < pin1.length(); i++) {
          stars += "*";
        }
        tft.println(stars);
      }
      delayMicroseconds(400);
    }
    if (cont_t_nxt == true) {
      tft.fillScreen(0x155b);
      tft.setTextColor(0xffff, 0x155b);
      disp_centered_text("Enter your PIN again", 80);
      disp_centered_text("* - Backspace", 190);
      disp_centered_text("# - Enter", 210);
      tft.fillRect(102, 135, 116, 32, 0x08c5);
      tft.setCursor(112, 140);
      tft.setTextColor(0xffff, 0x08c5);
      cont_t_nxt = false;
      bool setp2 = false;
      while (setp2 != true) {
        char key = keypad.getKey();
        if (key) {

          if (key == '#') {
            cont_t_nxt = true;
            setp2 = true;
          } else if (key == 'C') {
            cont_t_nxt = false;
            setp2 = true;
          } else if (key == '*') {
            pin2.remove(pin2.length() - 1, 1);
            tft.fillRect(102, 135, 116, 32, 0x08c5);
          } else {
            if (pin2.length() < 8)
              pin2 += key;
          }
          tft.setCursor(112, 140);
          tft.setTextColor(0xffff, 0x08c5);
          String stars;
          for (int i = 0; i < pin2.length(); i++) {
            stars += "*";
          }
          tft.println(stars);
        }
        delayMicroseconds(400);
      }
    }

    //Serial.println(pin1);
    //Serial.println(pin2);
    if (cont_t_nxt == true) {
      if (pin1.equals(pin2) && pin1.length() > 0) {
        for (int i = 0; i < 4; i++) {
          serp_key[i + 28] = read_cards[i];
        }
        String read_card;
        for (int i = 0; i < 4; i++) {
          if (read_cards[i] < 16)
            read_card += "0";
          read_card += String(read_cards[i], HEX);
        }
        String read_crd_bck = read_card;
        read_card += pin2;
        //Serial.println(read_card);
        gen_r = false;
        back_keys();
        dec_st = "";
        encrypt_hash_with_tdes_aes_blf_srp(read_card);
        rest_keys();
        int dec_st_len = dec_st.length() + 1;
        char dec_st_array[dec_st_len];
        dec_st.toCharArray(dec_st_array, dec_st_len);
        //Serial.println(dec_st);
        byte res[15];
        for (int i = 0; i < 30; i += 2) {
          if (i == 0) {
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
              res[i] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
              res[i] = 16 * getNum(dec_st_array[i + 34]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
              res[i] = getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
              res[i] = 0;
          } else {
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 34]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
              res[i / 2] = getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
              res[i / 2] = 0;
          }
        }
        String filenm = "/";
        for (int i = 0; i < 15; i++) {
          if (res[i] > 127)
            filenm += char(65 + (res[i] % 26));
          else
            filenm += char(97 + (res[i] % 26));
        }
        //Serial.println(filenm);
        gen_r = true;
        back_keys();
        dec_st = "";
        encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + "0.00");
        rest_keys();
        //Serial.println(dec_st);
        if (read_file(SPIFFS, filenm).equals("-1")) {
          write_to_file_with_overwrite(SPIFFS, filenm, dec_st);
          tft.setTextSize(2);
          tft.fillScreen(0x155b);
          tft.setTextColor(0xffff, 0x155b);
          disp_centered_text("Account Created", 90);
          disp_centered_text("Successfully", 115);
          delay(5000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keypad();
        } else {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Failed", 65);
          disp_centered_text("To Create An Account", 85);
          disp_centered_text("Account Already Exists", 115);
          disp_centered_text("Try Entering Different PIN", 150);
          delay(5000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keypad();
        }
      } else {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text("Failed", 65);
        disp_centered_text("To Create An Account", 85);
        disp_centered_text("PINs Don't Match", 115);
        delay(5000);
        disp_centered_text("Press Either '#' or 'C'", 220);
        press_key_on_keypad();
      }
    }
  }
  call_main_menu();
}

void view_account_balance() {
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff);
  disp_centered_text("Approximate the card to", 90);
  disp_centered_text("the RFID reader", 110);
  disp_centered_text("Press 'C' to Cancel", 220);
  bool cont_to_next_step = true;
  bool break_rfid_loop = false;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        read_cards[0] = rfid.uid.uidByte[0];
        read_cards[1] = rfid.uid.uidByte[1];
        read_cards[2] = rfid.uid.uidByte[2];
        read_cards[3] = rfid.uid.uidByte[3];
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    char key = keypad.getKey();
    if (key) {
      if (key == 'C') {
        cont_to_next_step = false;
        break_rfid_loop = true;
      }
    }
  }
  if (cont_to_next_step == true) {
    for (int i = 0; i < 4; i++) {
      serp_key[i + 28] = read_cards[i];
    }
    tft.fillScreen(0x155b);
    disp_centered_text("Enter Your PIN", 60);
    disp_centered_text("* - Backspace", 180);
    disp_centered_text("# - Enter", 200);
    disp_centered_text("C - Cancel", 220);
    tft.fillRect(102, 135, 116, 32, 0x08c5);
    tft.setCursor(112, 145);
    tft.setTextColor(0xffff, 0x08c5);
    cont_t_nxt = false;
    bool setp1 = false;
    String pin1;
    String pin2;
    while (setp1 != true) {
      char key = keypad.getKey();
      if (key) {

        if (key == '#') {
          cont_t_nxt = true;
          setp1 = true;
        } else if (key == 'C') {
          cont_t_nxt = false;
          setp1 = true;
        } else if (key == '*') {
          pin1.remove(pin1.length() - 1, 1);
          tft.fillRect(102, 135, 116, 32, 0x08c5);
        } else {
          if (pin1.length() < 8)
            pin1 += key;
        }
        tft.setCursor(112, 140);
        tft.setTextColor(0xffff, 0x08c5);
        String stars;
        for (int i = 0; i < pin1.length(); i++) {
          stars += "*";
        }
        tft.println(stars);
      }
      delayMicroseconds(400);
    }

    if (cont_t_nxt == true) {
      for (int i = 0; i < 4; i++) {
        serp_key[i + 28] = read_cards[i];
      }
      String read_card;
      for (int i = 0; i < 4; i++) {
        if (read_cards[i] < 16)
          read_card += "0";
        read_card += String(read_cards[i], HEX);
      }
      String read_crd_bck = read_card;
      read_card += pin1;
      //Serial.println(read_card);
      gen_r = false;
      back_keys();
      dec_st = "";
      encrypt_hash_with_tdes_aes_blf_srp(read_card);
      rest_keys();
      int dec_st_len = dec_st.length() + 1;
      char dec_st_array[dec_st_len];
      dec_st.toCharArray(dec_st_array, dec_st_len);
      //Serial.println(dec_st);
      byte res[15];
      for (int i = 0; i < 30; i += 2) {
        if (i == 0) {
          if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
            res[i] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
          if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
            res[i] = 16 * getNum(dec_st_array[i + 34]);
          if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
            res[i] = getNum(dec_st_array[i + 34 + 1]);
          if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
            res[i] = 0;
        } else {
          if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
            res[i / 2] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
          if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
            res[i / 2] = 16 * getNum(dec_st_array[i + 34]);
          if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
            res[i / 2] = getNum(dec_st_array[i + 34 + 1]);
          if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
            res[i / 2] = 0;
        }
      }
      String filenm = "/";
      for (int i = 0; i < 15; i++) {
        if (res[i] > 127)
          filenm += char(65 + (res[i] % 26));
        else
          filenm += char(97 + (res[i] % 26));
      }
      //Serial.println(filenm);
      gen_r = true;
      if (read_file(SPIFFS, filenm).equals("-1")) {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text("Error", 65);
        disp_centered_text("Account Does Not Exist", 85);
        delay(2000);
        disp_centered_text("Press Either '#' or 'C'", 220);
        press_key_on_keypad();
      } else {
        decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, filenm));
        bool balance_integrity = verify_integrity();
        if (balance_integrity == true) {
          String extr_crd;
          for (int i = 0; i < 8; i++)
            extr_crd += dec_st.charAt(i);
          //Serial.println(dec_st);
          //Serial.println(extr_crd);
          //Serial.println(read_crd_bck);
          if (read_crd_bck.equals(extr_crd)) {
            String ublc;
            for (int i = 8; i < dec_st.length(); i++)
              ublc += dec_st.charAt(i);
            tft.fillScreen(0x155b);
            tft.setTextColor(0xffff, 0x155b);
            tft.setTextSize(2);
            disp_centered_text("Your balance is:", 45);
            tft.setTextSize(text_size_for_sale);
            disp_centered_text(ublc + space_and_currency, 80);
            delay(100);
            tft.setTextSize(2);
            disp_centered_text("Press Either '#' or 'C'", 220);
            press_key_on_keypad();
          } else {
            tft.fillScreen(0x0000);
            tft.setTextSize(2);
            tft.setTextColor(five_six_five_red_color);
            disp_centered_text("System Error", 45);
            disp_centered_text("Record With Balance", 65);
            disp_centered_text("Doesn't Belong", 85);
            disp_centered_text("To This Card", 105);
            tft.setTextColor(0xffff);
            disp_centered_text("Please reboot", 180);
            disp_centered_text("the device", 200);
            disp_centered_text("and try again", 220);
            for (;;)
              delay(1000);
          }
        } else {
          tft.fillScreen(0x0000);
          tft.setTextSize(2);
          tft.setTextColor(five_six_five_red_color);
          disp_centered_text("System Error", 45);
          disp_centered_text("Integrity", 65);
          disp_centered_text("Verification", 85);
          disp_centered_text("Failed", 105);
          tft.setTextColor(0xffff);
          disp_centered_text("Please reboot", 180);
          disp_centered_text("the device", 200);
          disp_centered_text("and try again", 220);
          for (;;)
            delay(1000);
        }
      }
    }
  }
  call_main_menu();
}

void add_money_to_account() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Amount To Add");
  get_keypad_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Press '#'", 45);
  disp_centered_text("And Give The Device", 65);
  disp_centered_text("To The Client", 85);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_t_nxt = false;
  press_key_on_keypad();
  if (cont_t_nxt == true) {
    //Serial.println(keypad_input.toDouble());
    double amnt_to_add = keypad_input.toDouble();
    tft.setTextSize(2);
    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text("Put " + String(amnt_to_add, 2) + space_and_currency + " in", 70);
    disp_centered_text("Approximate the card to", 120);
    disp_centered_text("the RFID reader", 140);
    disp_centered_text("Press 'C' to Cancel", 220);

    bool cont_to_next_step = true;
    bool break_rfid_loop = false;
    while (break_rfid_loop == false) {
      if (rfid.PICC_IsNewCardPresent()) {
        if (rfid.PICC_ReadCardSerial()) {
          read_cards[0] = rfid.uid.uidByte[0];
          read_cards[1] = rfid.uid.uidByte[1];
          read_cards[2] = rfid.uid.uidByte[2];
          read_cards[3] = rfid.uid.uidByte[3];
          rfid.PICC_HaltA();
          rfid.PCD_StopCrypto1();
          break_rfid_loop = true;
        }
      }
      char key = keypad.getKey();
      if (key) {
        if (key == 'C') {
          cont_to_next_step = false;
          break_rfid_loop = true;
        }
      }
    }
    if (cont_to_next_step == true) {
      for (int i = 0; i < 4; i++) {
        serp_key[i + 28] = read_cards[i];
      }
      tft.fillScreen(0x155b);
      disp_centered_text("Enter Your PIN", 60);
      disp_centered_text("* - Backspace", 180);
      disp_centered_text("# - Enter", 200);
      disp_centered_text("C - Cancel", 220);
      tft.fillRect(102, 135, 116, 32, 0x08c5);
      tft.setCursor(112, 145);
      tft.setTextColor(0xffff, 0x08c5);
      cont_t_nxt = false;
      bool setp1 = false;
      String pin1;
      String pin2;
      while (setp1 != true) {
        char key = keypad.getKey();
        if (key) {

          if (key == '#') {
            cont_t_nxt = true;
            setp1 = true;
          } else if (key == 'C') {
            cont_t_nxt = false;
            setp1 = true;
          } else if (key == '*') {
            pin1.remove(pin1.length() - 1, 1);
            tft.fillRect(102, 135, 116, 32, 0x08c5);
          } else {
            if (pin1.length() < 8)
              pin1 += key;
          }
          tft.setCursor(112, 140);
          tft.setTextColor(0xffff, 0x08c5);
          String stars;
          for (int i = 0; i < pin1.length(); i++) {
            stars += "*";
          }
          tft.println(stars);
        }
        delayMicroseconds(400);
      }

      if (cont_t_nxt == true) {
        for (int i = 0; i < 4; i++) {
          serp_key[i + 28] = read_cards[i];
        }
        String read_card;
        for (int i = 0; i < 4; i++) {
          if (read_cards[i] < 16)
            read_card += "0";
          read_card += String(read_cards[i], HEX);
        }
        String read_crd_bck = read_card;
        read_card += pin1;
        //Serial.println(read_card);
        gen_r = false;
        back_keys();
        dec_st = "";
        encrypt_hash_with_tdes_aes_blf_srp(read_card);
        rest_keys();
        int dec_st_len = dec_st.length() + 1;
        char dec_st_array[dec_st_len];
        dec_st.toCharArray(dec_st_array, dec_st_len);
        //Serial.println(dec_st);
        byte res[15];
        for (int i = 0; i < 30; i += 2) {
          if (i == 0) {
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
              res[i] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
              res[i] = 16 * getNum(dec_st_array[i + 34]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
              res[i] = getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
              res[i] = 0;
          } else {
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 34]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
              res[i / 2] = getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
              res[i / 2] = 0;
          }
        }
        String filenm = "/";
        for (int i = 0; i < 15; i++) {
          if (res[i] > 127)
            filenm += char(65 + (res[i] % 26));
          else
            filenm += char(97 + (res[i] % 26));
        }
        //Serial.println(filenm);
        gen_r = true;
        if (read_file(SPIFFS, filenm).equals("-1")) {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Error", 65);
          disp_centered_text("Account Does Not Exist", 85);
          delay(2000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keypad();
        } else {
          decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, filenm));
          bool balance_integrity = verify_integrity();
          if (balance_integrity == true) {
            String extr_crd;
            for (int i = 0; i < 8; i++)
              extr_crd += dec_st.charAt(i);
            //Serial.println(dec_st);
            //Serial.println(extr_crd);
            //Serial.println(read_crd_bck);
            if (read_crd_bck.equals(extr_crd)) {
              String ublc;
              for (int i = 8; i < dec_st.length(); i++)
                ublc += dec_st.charAt(i);
              double new_bal = ublc.toDouble() + amnt_to_add;
              gen_r = true;
              back_keys();
              dec_st = "";
              //Serial.println(read_crd_bck);
              //Serial.println(extr_crd);
              //Serial.println(read_crd_bck + String(new_bal, 2));
              encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + String(new_bal, 2));
              rest_keys();
              write_to_file_with_overwrite(SPIFFS, filenm, dec_st);
              tft.fillScreen(0x155b);
              tft.setTextColor(0xffff, 0x155b);
              tft.setTextSize(3);
              disp_centered_text("Done!", 45);
              delay(100);
              tft.setTextSize(2);
              disp_centered_text("Press Either '#' or 'C'", 220);
              press_key_on_keypad();
            } else {
              tft.fillScreen(0x0000);
              tft.setTextSize(2);
              tft.setTextColor(five_six_five_red_color);
              disp_centered_text("System Error", 45);
              disp_centered_text("Record With Balance", 65);
              disp_centered_text("Doesn't Belong", 85);
              disp_centered_text("To This Card", 105);
              tft.setTextColor(0xffff);
              disp_centered_text("Please reboot", 180);
              disp_centered_text("the device", 200);
              disp_centered_text("and try again", 220);
              for (;;)
                delay(1000);
            }
          } else {
            tft.fillScreen(0x0000);
            tft.setTextSize(2);
            tft.setTextColor(five_six_five_red_color);
            disp_centered_text("System Error", 45);
            disp_centered_text("Integrity", 65);
            disp_centered_text("Verification", 85);
            disp_centered_text("Failed", 105);
            tft.setTextColor(0xffff);
            disp_centered_text("Please reboot", 180);
            disp_centered_text("the device", 200);
            disp_centered_text("and try again", 220);
            for (;;)
              delay(1000);
          }
        }
      }
    }
  }
}

void reduce_account_balance() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Sale Amount");
  get_keypad_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Press '#'", 45);
  disp_centered_text("And Give The Device", 65);
  disp_centered_text("To The Client", 85);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_t_nxt = false;
  press_key_on_keypad();
  if (cont_t_nxt == true) {
    //Serial.println(keypad_input.toDouble());
    double amnt_to_reduce = keypad_input.toDouble();
    tft.setTextSize(2);
    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text("Sale", 30);
    disp_centered_text(String(amnt_to_reduce, 2) + space_and_currency, 70);
    disp_centered_text("Approximate the card to", 120);
    disp_centered_text("the RFID reader", 140);
    disp_centered_text("Press 'C' to Cancel", 220);

    bool cont_to_next_step = true;
    bool break_rfid_loop = false;
    while (break_rfid_loop == false) {
      if (rfid.PICC_IsNewCardPresent()) {
        if (rfid.PICC_ReadCardSerial()) {
          read_cards[0] = rfid.uid.uidByte[0];
          read_cards[1] = rfid.uid.uidByte[1];
          read_cards[2] = rfid.uid.uidByte[2];
          read_cards[3] = rfid.uid.uidByte[3];
          rfid.PICC_HaltA();
          rfid.PCD_StopCrypto1();
          break_rfid_loop = true;
        }
      }
      char key = keypad.getKey();
      if (key) {
        if (key == 'C') {
          cont_to_next_step = false;
          break_rfid_loop = true;
        }
      }
    }
    if (cont_to_next_step == true) {
      for (int i = 0; i < 4; i++) {
        serp_key[i + 28] = read_cards[i];
      }
      tft.fillScreen(0x155b);
      disp_centered_text("Enter Your PIN", 60);
      disp_centered_text("* - Backspace", 180);
      disp_centered_text("# - Enter", 200);
      disp_centered_text("C - Cancel", 220);
      tft.fillRect(102, 135, 116, 32, 0x08c5);
      tft.setCursor(112, 145);
      tft.setTextColor(0xffff, 0x08c5);
      cont_t_nxt = false;
      bool setp1 = false;
      String pin1;
      String pin2;
      while (setp1 != true) {
        char key = keypad.getKey();
        if (key) {

          if (key == '#') {
            cont_t_nxt = true;
            setp1 = true;
          } else if (key == 'C') {
            cont_t_nxt = false;
            setp1 = true;
          } else if (key == '*') {
            pin1.remove(pin1.length() - 1, 1);
            tft.fillRect(102, 135, 116, 32, 0x08c5);
          } else {
            if (pin1.length() < 8)
              pin1 += key;
          }
          tft.setCursor(112, 140);
          tft.setTextColor(0xffff, 0x08c5);
          String stars;
          for (int i = 0; i < pin1.length(); i++) {
            stars += "*";
          }
          tft.println(stars);
        }
        delayMicroseconds(400);
      }

      if (cont_t_nxt == true) {
        for (int i = 0; i < 4; i++) {
          serp_key[i + 28] = read_cards[i];
        }
        String read_card;
        for (int i = 0; i < 4; i++) {
          if (read_cards[i] < 16)
            read_card += "0";
          read_card += String(read_cards[i], HEX);
        }
        String read_crd_bck = read_card;
        read_card += pin1;
        //Serial.println(read_card);
        gen_r = false;
        back_keys();
        dec_st = "";
        encrypt_hash_with_tdes_aes_blf_srp(read_card);
        rest_keys();
        int dec_st_len = dec_st.length() + 1;
        char dec_st_array[dec_st_len];
        dec_st.toCharArray(dec_st_array, dec_st_len);
        //Serial.println(dec_st);
        byte res[15];
        for (int i = 0; i < 30; i += 2) {
          if (i == 0) {
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
              res[i] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
              res[i] = 16 * getNum(dec_st_array[i + 34]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
              res[i] = getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
              res[i] = 0;
          } else {
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] != 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 34]) + getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] != 0 && dec_st_array[i + 34 + 1] == 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 34]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] != 0)
              res[i / 2] = getNum(dec_st_array[i + 34 + 1]);
            if (dec_st_array[i + 34] == 0 && dec_st_array[i + 34 + 1] == 0)
              res[i / 2] = 0;
          }
        }
        String filenm = "/";
        for (int i = 0; i < 15; i++) {
          if (res[i] > 127)
            filenm += char(65 + (res[i] % 26));
          else
            filenm += char(97 + (res[i] % 26));
        }
        //Serial.println(filenm);
        gen_r = true;
        if (read_file(SPIFFS, filenm).equals("-1")) {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Error", 65);
          disp_centered_text("Account Does Not Exist", 85);
          delay(2000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keypad();
        } else {
          decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, filenm));
          bool balance_integrity = verify_integrity();
          if (balance_integrity == true) {
            String extr_crd;
            for (int i = 0; i < 8; i++)
              extr_crd += dec_st.charAt(i);
            //Serial.println(dec_st);
            //Serial.println(extr_crd);
            //Serial.println(read_crd_bck);
            if (read_crd_bck.equals(extr_crd)) {
              String ublc;
              for (int i = 8; i < dec_st.length(); i++)
                ublc += dec_st.charAt(i);
              double new_bal = ublc.toDouble() - amnt_to_reduce;
              gen_r = true;
              back_keys();
              dec_st = "";
              if (new_bal >= 0){
                encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + String(new_bal, 2));
                rest_keys();
                write_to_file_with_overwrite(SPIFFS, filenm, dec_st);
                tft.fillScreen(0x155b);
                tft.setTextColor(0xffff, 0x155b);
                tft.setTextSize(3);
                disp_centered_text("Done!", 45);
                delay(100);
                tft.setTextSize(2);
                disp_centered_text("Press Either '#' or 'C'", 220);
                press_key_on_keypad();
              }
              else{
                tft.setTextSize(2);
                tft.fillScreen(0xf17f);
                tft.setTextColor(0xffff, 0xf17f);
                disp_centered_text("Not enough money in the", 90);
                disp_centered_text("account to complete the", 110);
                disp_centered_text("transaction", 130);
                delay(2000);
                disp_centered_text("Press Either '#' or 'C'", 220);
                press_key_on_keypad();
              }
            } else {
              tft.fillScreen(0x0000);
              tft.setTextSize(2);
              tft.setTextColor(five_six_five_red_color);
              disp_centered_text("System Error", 45);
              disp_centered_text("Record With Balance", 65);
              disp_centered_text("Doesn't Belong", 85);
              disp_centered_text("To This Card", 105);
              tft.setTextColor(0xffff);
              disp_centered_text("Please reboot", 180);
              disp_centered_text("the device", 200);
              disp_centered_text("and try again", 220);
              for (;;)
                delay(1000);
            }
          } else {
            tft.fillScreen(0x0000);
            tft.setTextSize(2);
            tft.setTextColor(five_six_five_red_color);
            disp_centered_text("System Error", 45);
            disp_centered_text("Integrity", 65);
            disp_centered_text("Verification", 85);
            disp_centered_text("Failed", 105);
            tft.setTextColor(0xffff);
            disp_centered_text("Please reboot", 180);
            disp_centered_text("the device", 200);
            disp_centered_text("and try again", 220);
            for (;;)
              delay(1000);
          }
        }
      }
    }
  }
}

void setup(void) {
  tft.begin();
  tft.fillScreen(0x0000);
  tft.setRotation(1);
  SPI.begin();
  rfid.PCD_Init();
  mvng_bc.createSprite(312, 61);
  mvng_bc.setColorDepth(16);
  gen_r = true;
  lock_scr_with_rfid();
  menu_pos = 0;
  m = 2; // Set AES to 256-bit mode
  clb_m = 4;
  Serial.begin(115200);
  //Serial.println(F("Inizializing FS..."));
  if (SPIFFS.begin(true)) {} else {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  continue_to_unlock();
  back_def_serp_k();
}

void loop() {
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_icon[i][j] == 1)
        mvng_bc.drawPixel(i, j, San_Francisco[(i + 4 + k) % 320][j + 98]);
    }
  }
  mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
  char key = keypad.getKey();
  if (key) {

    rest_def_serp_k();

    if (key == '8') {
      menu_pos--;
    } else if (key == '0') {
      menu_pos++;
    } else if (key == 'D') {
      lock_screen_keypad();
    } else if (key == '#') {
      approximate_operator_card_to_continue(menu_pos);
    }

    if (menu_pos > 3)
      menu_pos = 0;

    if (menu_pos < 0)
      menu_pos = 3;

    disp_menu();
  }
  delayMicroseconds(400);
  k++;
}
