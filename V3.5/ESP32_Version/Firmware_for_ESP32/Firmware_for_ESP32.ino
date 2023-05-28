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
// !!! Before uploading this sketch -
// Switch the partition scheme to the
// "Huge APP (3MB No OTA/1MB SPIFFS)" !!!
#include "FS.h"
#include "SD.h"
#include "SPI.h"
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
#include <PS2KeyAdvanced.h>
#include <PS2KeyMap.h>

#define IRQPIN 26
#define DATAPIN 27

#define MAX_NUM_OF_RECS 50

TFT_eSPI tft = TFT_eSPI();
TFT_eSprite mvng_bc = TFT_eSprite( & tft);

/*
 * RFID Reader - ESP32
 * SDA - D21
 * SCK - D18
 * MOSI - D23
 * MISO - D19
 * RST - D25
 */

#define SS_PIN 21
#define RST_PIN 25

MFRC522 rfid(SS_PIN, RST_PIN);

byte read_cards[16];

DES des;
Blowfish blowfish;

PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

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
String keyboard_input;
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
bool sd_mnt;

// Keys (Below)
String kderalgs = "uj9AFDCL175Ug9AA5aUJc96ySjrO1j7QK";
int numofkincr = 697;
byte hmackey[] = {"9fT7FSHWZ1a28H0kc97cj3N80eO96KLvWEAMEA1xoRljx7w095FP215CVVn33H24g62Aya8h56O6Oda4Jh7SvRW1e6m9s588n7g9aADlNBz0tDr4B97D9KWB"};
byte des_key[] = {
0xb9,0x9b,0xf5,0xb5,0x09,0x47,0x00,0xad,
0xff,0x0a,0x0a,0x3d,0x21,0x8e,0xf6,0xc2,
0x80,0x1e,0xad,0x3a,0xfc,0xe6,0xdd,0xe5
};
uint8_t AES_key[32] = {
0xaa,0xe9,0x60,0xd7,
0x4d,0x12,0xc6,0xff,
0xa8,0x73,0x02,0x4a,
0x55,0x6f,0xf6,0xaa,
0x99,0x3d,0xe6,0x20,
0x9d,0x57,0xe4,0x23,
0x91,0xc7,0x46,0x74,
0x56,0xed,0x83,0x41
};
unsigned char Blwfsh_key[] = {
0xde,0x00,0xe7,0x0c,
0xc2,0xde,0xf0,0x6e,
0xf8,0xc3,0x21,0xe8,
0xaa,0x30,0x5e,0xec,
0x93,0xee,0xf9,0x21,
0xd4,0x49,0x57,0xaf
};
uint8_t serp_key[32] = {
0xba,0x06,0xfa,0x69,
0x71,0x14,0xb0,0x91,
0x8f,0xd3,0x30,0xb9,
0xb2,0x43,0x3e,0x3b,
0x8a,0xcc,0xe3,0xef,
0x9a,0xaf,0xa4,0xd4,
0x9d,0x4f,0xba,0xfb,
0x19,0x46,0xf6,0xb9
};
uint8_t second_AES_key[32] = {
0x8d,0x37,0x7a,0x18,
0x36,0x7f,0xc1,0xae,
0xa4,0x4f,0x09,0x16,
0x6b,0xef,0xd1,0xdc,
0x7f,0xeb,0x2d,0x5c,
0x88,0xc5,0xd1,0x4d,
0x13,0xb8,0xe1,0xd7,
0xa4,0xfd,0x0a,0xeb
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
  keyboard_input = "";
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

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (keyboard_input.length() > 0)
    curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
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
  //gfx->fillScreen(0x0000);
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

void keyb_input() {
  finish_input = false;
  while (finish_input == false) {

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            act = false;
            finish_input = true;
          } else if ((code & 0xFF) == 13) { // Enter
            finish_input = true;
          } else if ((code & 0xFF) == 8) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            tft.fillRect(0, 48, 312, 192, 0x0000);
            //Serial.println(keyboard_input);
            check_bounds_and_change_char();
            disp();
          } else {
            keyboard_input += char(code & 0xFF);
            check_bounds_and_change_char();
            disp();
          }
        }

      }
    }

    delayMicroseconds(400);
  }
}

void star_keyb_input() {
  finish_input = false;
  while (finish_input == false) {

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {
          if ((code & 0xFF) == 13) { // Enter
            finish_input = true;
          } else if ((code & 0xFF) == 8) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            tft.fillRect(0, 48, 312, 192, 0x0000);
            //Serial.println(keyboard_input);
            check_bounds_and_change_char();
            disp_stars();
          } else {
            keyboard_input += char(code & 0xFF);
            check_bounds_and_change_char();
            disp_stars();
          }
        }

      }
    }
    delayMicroseconds(400);
  }
}

// Functions that work with files on SD card (Below)

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

// Functions that work with files on SD card (Above)

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {
          break_the_loop = true;
        }

      }
    }
    delayMicroseconds(400);
  }
}

void continue_to_unlock() {
  keyboard_input = "";
  if (read_file(SD, "/kppass").equals("-1"))
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
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Master Password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
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
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
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

  write_to_file_with_overwrite(SD, "/kppass", dec_st);
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
  write_to_file_with_overwrite(SD, "/oprcrd", dec_st);
}

void modify_keys() {
  keyboard_input += kderalgs;
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
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
  star_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  disp_centered_text("Unlocking", 45);
  disp_centered_text("KhadashPay", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
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
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
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
  //Serial.println(read_file(SD, "/kppass"));
  decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SD, "/kppass"));
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

void disp_centered_text_b_w(String text, int h) {
  tft.setTextColor(0x0882);
  tft.drawCentreString(text, 160, h - 1, 1);
  tft.drawCentreString(text, 160, h + 1, 1);
  tft.drawCentreString(text, 159, h, 1);
  tft.drawCentreString(text, 161, h, 1);
  tft.setTextColor(0xf7de);
  tft.drawCentreString(text, 160, h, 1);
}

int chosen_lock_screen;
unsigned int k;

void display_letters_with_shifting_background() {

  if (chosen_lock_screen == 0) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Austin[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 1) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Beirut[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 2) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Bellevue[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 3) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Colorado_Springs[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 4) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Frankfurt[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 5) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Gaborone[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 6) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Greenwich[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 7) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, London[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 8) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Miami[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 9) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Minneapolis[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 10) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Montreal[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  if (chosen_lock_screen == 11) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Tel_Aviv[(i + 4 + k) % 320][j + 120]);
      }
    }
  }

  mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
  k++;
}

void display_lock_screen() {
  if (chosen_lock_screen == 0) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Austin[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 1) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Beirut[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Bellevue[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 3) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Colorado_Springs[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 4) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Frankfurt[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 5) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Gaborone[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 6) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Greenwich[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 7) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, London[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 8) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Miami[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 9) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Minneapolis[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 10) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Montreal[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 11) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Tel_Aviv[i][j]);
      }
    }
  }

  delay(500);

  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_per[i][j] == 1)
        tft.drawPixel(i + 4, j + 10, 0xf7de);
    }
  }

  mvng_bc.createSprite(312, 61);
  mvng_bc.setColorDepth(16);
  mvng_bc.fillSprite(TFT_TRANSPARENT);
}

void lock_scr_with_rfid() {
  chosen_lock_screen = esp_random() % 12;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Tap RFID card N1", 205);
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
    new_screen = esp_random() % 12;
  }
  chosen_lock_screen = new_screen;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Tap RFID card N2", 205);
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
    new_screen = esp_random() % 12;
  }
  chosen_lock_screen = new_screen;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Tap RFID card N3", 205);
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
    new_screen = esp_random() % 12;
  }
  chosen_lock_screen = new_screen;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Tap RFID card N4", 205);
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

void lock_scr_no_sd_card() {
  chosen_lock_screen = esp_random() % 12;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("No SD Card", 209);
  bool break_rfid_loop = false;
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  k = 0;
  while (break_rfid_loop == false) {
    if (rfid.PICC_IsNewCardPresent()) {
      if (rfid.PICC_ReadCardSerial()) {
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        break_rfid_loop = true;
      }
    }
    display_letters_with_shifting_background();
  }
}

// Menu (Below)
void call_main_menu() {
  menu_pos = 0;
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
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    tft.setTextColor(0xffff);
    disp_centered_text("Put Money In", 120);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    tft.setTextColor(0xffff);
    disp_centered_text("New Account", 140);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Balance", 160);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    tft.setTextColor(0xffff);
    disp_centered_text("View Balance", 160);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
    tft.setTextColor(0xffff);
    disp_centered_text("Other Options", 180);
  }
}

void lock_screen_keyboard() {
  chosen_lock_screen = esp_random() % 12;
  display_lock_screen();
  tft.setTextSize(1);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("github.com/Northstrix/KhadashPay", 230);
  bool break_loop = false;
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  k = 0;
  while (break_loop == false) {
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {
          break_loop = true;
        }

      }
    }
    display_letters_with_shifting_background();
  }
  call_main_menu();
  //mvng_bc.deleteSprite();
}
// Menu (Above)

void tab_or_encdr_bttn_to_print() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    if (keyboard.available()) {
      c = keyboard.read();
      if (c == 285) {
        act = true;
        break_the_loop = true;
      } else
        break_the_loop = true;
    }
    delayMicroseconds(400);
  }
}

void disp_button_designation() {
  tft.setTextSize(1);
  tft.setTextColor(0x07e0);
  tft.setCursor(0, 232);
  tft.print("'Enter' - continue                     ");
  tft.setTextColor(five_six_five_red_color);
  tft.print("'Esc' - cancel");
}

void disp_button_designation_for_del() {
  tft.setTextSize(1);
  tft.setTextColor(five_six_five_red_color);
  tft.setCursor(0, 232);
  tft.print("'Enter' - continue                     ");
  tft.setTextColor(0x07e0);
  tft.print("'Esc' - cancel");
}

void disp_paste_smth_inscr(String what_to_pst) {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  disp_centered_text("Paste " + what_to_pst + " to", 30);
  disp_centered_text("the Serial Terminal", 50);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press any key", 200);
  disp_centered_text("to cancel", 220);
}

void disp_paste_cphrt_inscr() {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  disp_centered_text("Paste Ciphertext to", 30);
  disp_centered_text("the Serial Terminal", 50);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press any key", 200);
  disp_centered_text("to cancel", 220);
}

void disp_plt_on_tft(bool intgrt) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Plaintext", 10);
  if (intgrt == true)
    tft.setTextColor(0xffff);
  else {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Integrity Verification failed!!!", 232);
  }
  disp_centered_text(dec_st, 30);
}

void call_oth_opt_menu() {
  tft.fillScreen(0x0000);
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_per[i][j] == 1 || khadash_pay_icon[i][j] == 1)
        tft.drawPixel(i + 4, j + 10, 0xf7de);
    }
  }
  disp_oth_opt_menu();
}

void disp_oth_opt_menu() {
  tft.setTextSize(2);
  if (menu_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Logins", 100);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encrypt String", 120);
    disp_centered_text("Decrypt String", 140);
  }
  if (menu_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", 100);
    tft.setTextColor(0xffff);
    disp_centered_text("Encrypt String", 120);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Decrypt String", 140);
  }
  if (menu_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", 100);
    disp_centered_text("Encrypt String", 120);
    tft.setTextColor(0xffff);
    disp_centered_text("Decrypt String", 140);
  }
}

void action_for_oth_opt() {
  tft.fillScreen(0x0000);
  menu_pos = 0;
  gen_r = true;
  call_oth_opt_menu();
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, London[(i + 4 + k) % 320][j + 98]);
      }
    }
    mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c == 279 || c == 56)
        menu_pos--;

      if (c == 280 || c == 48)
        menu_pos++;

      if (menu_pos < 0)
        menu_pos = 2;

      if (menu_pos > 2)
        menu_pos = 0;

      if ((c & 0xFF) == 30) {
        if (menu_pos == 0) {
          action_for_data_in_flash("Logins Menu");
          cont_to_next_el = true;
        }

        if (menu_pos == 1) {
          input_source_for_encr_algs();
          cont_to_next_el = true;
        }

        if (menu_pos == 2) {
          where_to_print_plaintext();
          cont_to_next_el = true;
        }
      }

      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      disp_oth_opt_menu();

    }
    delayMicroseconds(400);
    k++;
  }
  call_main_menu();
}

void where_to_print_plaintext_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void where_to_print_plaintext() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Where to print plaintext?", 10);
  curr_key = 0;
  where_to_print_plaintext_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if ((c & 0xFF) == 30) {

        if (curr_key == 0) {
          decr_TDES_AES_BLF_Serp(true);
          cont_to_next_el = true;
        }

        if (curr_key == 1) {
          decr_TDES_AES_BLF_Serp(false);
          cont_to_next_el = true;
        }
      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      where_to_print_plaintext_menu(curr_key);

    }
  }
  call_main_menu();
}

void input_source_for_encr_algs_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_encr_algs() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_encr_algs_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if ((c & 0xFF) == 30) {

        if (curr_key == 0) {
          encr_TDES_AES_BLF_Serp();
          cont_to_next_el = true;
        }

        if (curr_key == 1) {
          encr_TDES_AES_BLF_Serp_from_Serial();
          cont_to_next_el = true;
        }

      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      input_source_for_encr_algs_menu(curr_key);

    }
  }
  call_main_menu();
}

void encr_TDES_AES_BLF_Serp() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_string_with_tdes_aes_blf_srp(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_TDES_AES_BLF_Serp_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();

        canc_op = true;
        break;

      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_string_with_tdes_aes_blf_srp(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_TDES_AES_BLF_Serp(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();

        canc_op = true;
        break;

      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void action_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("View", sdown + 70);
  }
}

void action_for_data_in_flash(String menu_title) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {

    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if ((c & 0xFF) == 30) {
        if (curr_key == 0) {
          select_login(0);
          cont_to_next_el = true;
        }

        if (curr_key == 1) {
          select_login(1);
          cont_to_next_el = true;
        }

        if (curr_key == 2) {
          select_login(2);
          cont_to_next_el = true;
        }

        if (curr_key == 3) {
          select_login(3);
          cont_to_next_el = true;
        }
      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      action_for_data_in_flash_menu(curr_key);
    }
  }
  call_main_menu();
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

byte input_source_for_data_in_flash() {
  byte inpsrc = 0;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if ((c & 0xFF) == 30) {
        if (curr_key == 0) {
          inpsrc = 1;
        }

        if (curr_key == 1) {
          inpsrc = 2;
        }
        cont_to_next_el = true;
        break;
      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
        break;
      }
      input_source_for_data_in_flash_menu(curr_key);

    }
  }
  return inpsrc;
}

// Functions for Logins (Below)

void select_login(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Edit login
  // 2 - Delete login
  // 3 - View login
  delay(200);
  curr_key = 1;
  header_for_select_login(what_to_do_with_it);
  display_title_from_login_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();

      if (c == 278 || c == 57)
        curr_key++;

      if (c == 277 || c == 56)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if ((c & 0xFF) == 30) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_login_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_login_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            edit_login_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_login_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          delete_login(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          view_login(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if ((c & 0xFF) == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(200);
      header_for_select_login(what_to_do_with_it);
      display_title_from_login_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_login(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_login_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file(SD, "/L" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_login_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_login(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_login(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  keyb_input();
  if (act == true) {
    enter_username_for_login(chsn_slot, keyboard_input);
  }
  return;
}

void enter_username_for_login(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Username");
  keyb_input();
  if (act == true) {
    enter_password_for_login(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void enter_password_for_login(int chsn_slot, String entered_title, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Password");
  keyb_input();
  if (act == true) {
    enter_website_for_login(chsn_slot, entered_title, entered_username, keyboard_input);
  }
  return;
}

void enter_website_for_login(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Website");
  keyb_input();
  if (act == true) {
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, keyboard_input);
  }
  return;
}

void add_login_from_serial(int chsn_slot) {
  get_title_for_login_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_login_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_username_for_login_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_username_for_login_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Username");
    Serial.println("\nPaste the username here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_password_for_login_from_serial(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_password_for_login_from_serial(int chsn_slot, String entered_title, String entered_username) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Password");
    Serial.println("\nPaste the password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_website_for_login_from_serial(chsn_slot, entered_title, entered_username, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_website_for_login_from_serial(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Website");
    Serial.println("\nPaste the website here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_login_to_flash(int chsn_slot, String entered_title, String entered_username, String entered_password, String entered_website) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_username);
  Serial.println(entered_password);
  Serial.println(entered_website);
  */
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding login to the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_username);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_usn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_password);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_psw", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_website);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_wbs", dec_st);
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(entered_title + entered_username + entered_password + entered_website);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_login_and_tag(int chsn_slot, String new_password) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing login in the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_password);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_psw", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_usn"));
  String decrypted_username = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_wbs"));
  String decrypted_website = dec_st;

  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(decrypted_title + decrypted_username + new_password + decrypted_website);
  delay(200);
  write_to_file_with_overwrite(SD, "/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_login_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file(SD, "/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_psw"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Password");
    keyboard_input = old_password;
    disp();
    keyb_input();
    if (act == true) {
      update_login_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void edit_login_from_serial(int chsn_slot) {
  if (read_file(SD, "/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Password");
      Serial.println("\nPaste new password here:");
      bool canc_op = false;
      while (!Serial.available()) {
        if (keyboard.available()) {
          c = keyboard.read();
          if (c > 0 && ((c & 0xFF) != 6)) {
            if (c >> 8 == 192 && (c & PS2_BREAK)) {
              canc_op = true;
              break;
            }
            if (c >> 8 == 129 && (c & PS2_BREAK)) {
              canc_op = true;
              break;
            }
            if (c >> 8 == 128 && (c & PS2_BREAK)) {
              canc_op = true;
              break;
            }
          }
        }

        delayMicroseconds(400);
      }
      if (canc_op == true)
        break;
      update_login_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_login(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting login from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file(SD, "/L" + String(chsn_slot) + "_tag");
  delete_file(SD, "/L" + String(chsn_slot) + "_ttl");
  delete_file(SD, "/L" + String(chsn_slot) + "_usn");
  delete_file(SD, "/L" + String(chsn_slot) + "_psw");
  delete_file(SD, "/L" + String(chsn_slot) + "_wbs");
  clear_variables();
  call_main_menu();
  return;
}

void view_login(int chsn_slot) {
  if (read_file(SD, "/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SD, "/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    act = false;
    tab_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Username:\"");
      Serial.print(decrypted_username);
      Serial.println("\"");
      Serial.print("Password:\"");
      Serial.print(decrypted_password);
      Serial.println("\"");
      Serial.print("Website:\"");
      Serial.print(decrypted_website);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!");
      } else {
        Serial.println("Integrity Verification Failed!!!");
      }
    }
  }
}

// Functions for Logins (Above)

void press_key_on_keyboard() {
  bool break_loop = false;
  while (break_loop == false) {
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            cont_t_nxt = false;
            break_loop = true;
          } else if ((code & 0xFF) == 13) { // Enter
            cont_t_nxt = true;
            break_loop = true;
          }
        }

      }
    }

    delayMicroseconds(400);
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
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            cont_to_next_step = false;
            break_rfid_loop = true;
          }
        }

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
    //Serial.println(read_file(SD, "/oprcrd"));
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SD, "/oprcrd"));
    //Serial.println(dec_tag);
    //Serial.println(hashed_card);
    for (int i = 10; i < 28; i++) {
      serp_key[i] = authCode[i];
    }
    if (dec_tag.equals(hashed_card) && cps > 1) {
      if (cps < 4) {
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(0xffff);
        disp_centered_text("Press '#'", 45);
        disp_centered_text("And Give The Device", 65);
        disp_centered_text("To The Client", 85);
        disp_centered_text("Press 'C' to Cancel", 220);
        cont_t_nxt = false;
        press_key_on_keyboard();
      } else {
        cont_t_nxt = true;
      }
      if (cont_t_nxt == true) {
        if (cps == 2)
          create_new_account();
        if (cps == 3)
          view_account_balance();
        if (cps == 4)
          action_for_oth_opt();
      }
    } else if (dec_tag.equals(hashed_card) && cps < 2) {
      if (cps == 0)
        reduce_account_balance();
      if (cps == 1)
        add_money_to_account();
    } else {
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
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            cont_to_next_step = false;
            break_rfid_loop = true;
          }
        }
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

      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_t_nxt = false;
              setp1 = true;
            } else if ((code & 0xFF) == 13) { // Enter
              cont_t_nxt = true;
              setp1 = true;
            } else if ((code & 0xFF) == 8) { // Backspace
              pin1.remove(pin1.length() - 1, 1);
              tft.fillRect(102, 135, 116, 32, 0x08c5);
            } else {
              if (pin1.length() < 8)
                pin1 += char(code & 0xFF);
            }

            tft.setCursor(112, 140);
            tft.setTextColor(0xffff, 0x08c5);
            String stars;
            for (int i = 0; i < pin1.length(); i++) {
              stars += "*";
            }
            tft.println(stars);
          }

        }
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

        code = keyboard.available();
        if (code > 0) {
          code = keyboard.read();
          code = keymap.remapKey(code);
          if (code > 0) {
            if ((code & 0xFF)) {

              if ((code & 0xFF) == 27) { // Esc
                cont_t_nxt = false;
                setp2 = true;
              } else if ((code & 0xFF) == 13) { // Enter
                cont_t_nxt = true;
                setp2 = true;
              } else if ((code & 0xFF) == 8) { // Backspace
                pin2.remove(pin2.length() - 1, 1);
                tft.fillRect(102, 135, 116, 32, 0x08c5);
              } else {
                if (pin2.length() < 8)
                  pin2 += char(code & 0xFF);
              }

              tft.setCursor(112, 140);
              tft.setTextColor(0xffff, 0x08c5);
              String stars;
              for (int i = 0; i < pin2.length(); i++) {
                stars += "*";
              }
              tft.println(stars);
            }

          }
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
        if (read_file(SD, filenm).equals("-1")) {
          write_to_file_with_overwrite(SD, filenm, dec_st);
          tft.setTextSize(2);
          tft.fillScreen(0x155b);
          tft.setTextColor(0xffff, 0x155b);
          disp_centered_text("Account Created", 90);
          disp_centered_text("Successfully", 115);
          delay(3500);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        } else {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Failed", 65);
          disp_centered_text("To Create An Account", 85);
          disp_centered_text("Account Already Exists", 115);
          disp_centered_text("Try Entering Different PIN", 150);
          delay(3500);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        }
      } else {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text("Failed", 65);
        disp_centered_text("To Create An Account", 85);
        disp_centered_text("PINs Don't Match", 115);
        delay(3500);
        disp_centered_text("Press Either '#' or 'C'", 220);
        press_key_on_keyboard();
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
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            cont_to_next_step = false;
            break_rfid_loop = true;
          }
        }
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
    while (setp1 != true) {

      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_t_nxt = false;
              setp1 = true;
            } else if ((code & 0xFF) == 13) { // Enter
              cont_t_nxt = true;
              setp1 = true;
            } else if ((code & 0xFF) == 8) { // Backspace
              pin1.remove(pin1.length() - 1, 1);
              tft.fillRect(102, 135, 116, 32, 0x08c5);
            } else {
              if (pin1.length() < 8)
                pin1 += char(code & 0xFF);
            }

            tft.setCursor(112, 140);
            tft.setTextColor(0xffff, 0x08c5);
            String stars;
            for (int i = 0; i < pin1.length(); i++) {
              stars += "*";
            }
            tft.println(stars);
          }

        }
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
      if (read_file(SD, filenm).equals("-1")) {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text("Error", 65);
        disp_centered_text("Account Does Not Exist", 85);
        delay(2000);
        disp_centered_text("Press Either '#' or 'C'", 220);
        press_key_on_keyboard();
      } else {
        decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(SD, filenm));
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
            press_key_on_keyboard();
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
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Press '#'", 45);
  disp_centered_text("And Give The Device", 65);
  disp_centered_text("To The Client", 85);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_t_nxt = false;
  press_key_on_keyboard();
  if (cont_t_nxt == true) {
    //Serial.println(keyboard_input.toDouble());
    keyboard_input.replace(",", ".");
    double amnt_to_add = keyboard_input.toDouble();
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
      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_to_next_step = false;
              break_rfid_loop = true;
            }
          }
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
      while (setp1 != true) {

        code = keyboard.available();
        if (code > 0) {
          code = keyboard.read();
          code = keymap.remapKey(code);
          if (code > 0) {
            if ((code & 0xFF)) {

              if ((code & 0xFF) == 27) { // Esc
                cont_t_nxt = false;
                setp1 = true;
              } else if ((code & 0xFF) == 13) { // Enter
                cont_t_nxt = true;
                setp1 = true;
              } else if ((code & 0xFF) == 8) { // Backspace
                pin1.remove(pin1.length() - 1, 1);
                tft.fillRect(102, 135, 116, 32, 0x08c5);
              } else {
                if (pin1.length() < 8)
                  pin1 += char(code & 0xFF);
              }

              tft.setCursor(112, 140);
              tft.setTextColor(0xffff, 0x08c5);
              String stars;
              for (int i = 0; i < pin1.length(); i++) {
                stars += "*";
              }
              tft.println(stars);
            }

          }
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
        if (read_file(SD, filenm).equals("-1")) {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Error", 65);
          disp_centered_text("Account Does Not Exist", 85);
          delay(2000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        } else {
          decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(SD, filenm));
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
              write_to_file_with_overwrite(SD, filenm, dec_st);
              tft.fillScreen(0x155b);
              tft.setTextColor(0xffff, 0x155b);
              tft.setTextSize(3);
              disp_centered_text("Done!", 45);
              delay(100);
              tft.setTextSize(2);
              disp_centered_text("Press Either '#' or 'C'", 220);
              press_key_on_keyboard();
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
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Press '#'", 45);
  disp_centered_text("And Give The Device", 65);
  disp_centered_text("To The Client", 85);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_t_nxt = false;
  press_key_on_keyboard();
  if (cont_t_nxt == true) {
    //Serial.println(keyboard_input.toDouble());
    keyboard_input.replace(",", ".");
    double amnt_to_reduce = keyboard_input.toDouble();
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
      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_to_next_step = false;
              break_rfid_loop = true;
            }
          }
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
      while (setp1 != true) {

        code = keyboard.available();
        if (code > 0) {
          code = keyboard.read();
          code = keymap.remapKey(code);
          if (code > 0) {
            if ((code & 0xFF)) {

              if ((code & 0xFF) == 27) { // Esc
                cont_t_nxt = false;
                setp1 = true;
              } else if ((code & 0xFF) == 13) { // Enter
                cont_t_nxt = true;
                setp1 = true;
              } else if ((code & 0xFF) == 8) { // Backspace
                pin1.remove(pin1.length() - 1, 1);
                tft.fillRect(102, 135, 116, 32, 0x08c5);
              } else {
                if (pin1.length() < 8)
                  pin1 += char(code & 0xFF);
              }

              tft.setCursor(112, 140);
              tft.setTextColor(0xffff, 0x08c5);
              String stars;
              for (int i = 0; i < pin1.length(); i++) {
                stars += "*";
              }
              tft.println(stars);
            }

          }
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
        if (read_file(SD, filenm).equals("-1")) {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Error", 65);
          disp_centered_text("Account Does Not Exist", 85);
          delay(2000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        } else {
          decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(SD, filenm));
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
              if (new_bal >= 0) {
                encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + String(new_bal, 2));
                rest_keys();
                write_to_file_with_overwrite(SD, filenm, dec_st);
                tft.fillScreen(0x155b);
                tft.setTextColor(0xffff, 0x155b);
                tft.setTextSize(3);
                disp_centered_text("Done!", 45);
                delay(100);
                tft.setTextSize(2);
                disp_centered_text("Press Either '#' or 'C'", 220);
                press_key_on_keyboard();
              } else {
                tft.setTextSize(2);
                tft.fillScreen(0xf17f);
                tft.setTextColor(0xffff, 0xf17f);
                disp_centered_text("Not enough money in the", 90);
                disp_centered_text("account to complete the", 110);
                disp_centered_text("transaction", 130);
                delay(2000);
                disp_centered_text("Press Either '#' or 'C'", 220);
                press_key_on_keyboard();
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
  mvng_bc.createSprite(312, 61);
  mvng_bc.setColorDepth(16);
  gen_r = true;
  keyboard.begin(DATAPIN, IRQPIN);
  keyboard.setNoBreak(1);
  keyboard.setNoRepeat(1);
  keymap.selectMap((char * )
    "US");
  menu_pos = 0;
  m = 2; // Set AES to 256-bit mode
  clb_m = 4;
  Serial.begin(115200);
  SPI.begin(); // init SPI bus
  rfid.PCD_Init(); // init MFRC522
  if (!SD.begin(5)) {
    sd_mnt = false;
    //Serial.println("Card Mount Failed");
  } else {
    sd_mnt = true;
  }

  if (sd_mnt == true)
    lock_scr_with_rfid();
  else {
    while (sd_mnt == false) {
      lock_scr_no_sd_card();
      if (SD.begin(5)) {
        sd_mnt = true;
        lock_scr_with_rfid();
      }
    }
  }
  continue_to_unlock();
  back_def_serp_k();
}

void loop() {
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_icon[i][j] == 1)
        mvng_bc.drawPixel(i, j, Frankfurt[(i + 4 + k) % 320][j + 98]);
    }
  }
  mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);

  if (keyboard.available()) {
    //Serial.println(int(c));
    c = keyboard.read();
    rest_def_serp_k();
    if (c == 279 || c == 56)
      menu_pos--;

    if (c == 280 || c == 48)
      menu_pos++;

    if (menu_pos < 0)
      menu_pos = 4;

    if (menu_pos > 4)
      menu_pos = 0;

    if ((c & 0xFF) == 30)
      approximate_operator_card_to_continue(menu_pos);

    if (c == 61) {
      lock_screen_keyboard();
    }
    disp_menu();

  }
  delayMicroseconds(400);
  k++;
}
