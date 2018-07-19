//Original file: https://github.com/adafruit/Adafruit-PN532/blob/master/Adafruit_PN532.h

bool readPassiveTargetID2(uint8_t cardbaudrate, uint8_t * uid, uint8_t * uidLength, uint8_t * uid2, uint8_t * uidLength2, uint16_t timeout = 0); //timeout 0 means no timeout - will block forever.
uint8_t mifareclassic_AuthenticateBlock2 (uint8_t * uid, uint8_t uidLen, uint32_t blockNumber, uint8_t keyNumber, uint8_t * keyData, uint8_t tagActive);
uint8_t mifareclassic_ReadDataBlock2 (uint8_t blockNumber, uint8_t * data, uint8_t tagActive);
