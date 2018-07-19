//Original files:
// - https://github.com/adafruit/Adafruit-PN532/blob/master/examples/iso14443a_uid/iso14443a_uid.pde
// - https://github.com/adafruit/Adafruit-PN532/blob/master/examples/mifareclassic_memdump/mifareclassic_memdump.pde
//
#include <Wire.h>
#include <SPI.h>
#include <Adafruit_PN532.h>

#define PN532_SCK  (2)
#define PN532_MOSI (3)
#define PN532_SS   (4)
#define PN532_MISO (5)
Adafruit_PN532 nfc(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);
void setup() {
  Serial.begin(115200);
  while (!Serial);
  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }
  
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX); 
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC); 
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);
  // Set the max number of retry attempts to read from a card
  // This prevents us from waiting forever for a card, which is
  // the default behaviour of the PN532.
  nfc.setPassiveActivationRetries(0xFF);
  
  // configure board to read RFID tags
  nfc.SAMConfig();
}

void readm(uint8_t *uid, uint8_t uidLength, uint8_t tagA){ //, uint8_t *uid2, uint8_t uidLength2
  uint8_t success;                          // Flag to check if there was an error with the PN532
  uint8_t currentblock = 0;                 // Counter to keep track of which block we're on
  bool authenticated = false;               // Flag to indicate if the sector is authenticated
  uint8_t data[16];                         // Array to store block data during reads

  // Keyb on NDEF and Mifare Classic should be the same
  uint8_t keyuniversal[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  if (uidLength == 4){
    // We probably have a Mifare Classic card ...
    Serial.println("Seems to be a Mifare Classic card (4 byte UID)");
    
    // Now we try to go through all 16 sectors (each having 4 blocks)
    // authenticating each sector, and then dumping the blocks
    for (currentblock = 0; currentblock < 64; currentblock++) {
      // Check if this is a new block so that we can reauthenticate
      if (nfc.mifareclassic_IsFirstBlock(currentblock)) authenticated = false;
      // If the sector hasn't been authenticated, do so first
      if (!authenticated){
        // Starting of a new sector ... try to to authenticate
        Serial.print("------------------------Sector ");Serial.print(currentblock/4, DEC);Serial.println("-------------------------");
        if (currentblock == 0){
            // This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
            // or 0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 for NDEF formatted cards using key a,
            // but keyb should be the same for both (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)
            success = nfc.mifareclassic_AuthenticateBlock2 (uid, uidLength, currentblock, 1, keyuniversal, tagA);
            //Serial.print("------------------------Intentando: ");
        }
        else{
            // This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
            // or 0xD3 0xF7 0xD3 0xF7 0xD3 0xF7 for NDEF formatted cards using key a,
            // but keyb should be the same for both (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)
            success = nfc.mifareclassic_AuthenticateBlock2 (uid, uidLength, currentblock, 1, keyuniversal, tagA);
        }
        if (success){
          authenticated = true;
        }
        else{
          Serial.println("Authentication error");
        }
      }
      // If we're still not authenticated just skip the block
      if (!authenticated) {
        Serial.print("Block ");Serial.print(currentblock, DEC);Serial.println(" unable to authenticate");
      }
      else{
        // Authenticated ... we should be able to read the block now
        // Dump the data into the 'data' array
        success = nfc.mifareclassic_ReadDataBlock2(currentblock, data, tagA);
        if (success){
          // Read successful
          Serial.print("Block ");Serial.print(currentblock, DEC);
          if (currentblock < 10){
            Serial.print("  ");
          }
          else {
            Serial.print(" ");
          }
          // Dump the raw data
          nfc.PrintHexChar(data, 16);
        }
        else{
          // Oops ... something happened
          Serial.print("Block ");Serial.print(currentblock, DEC);
          Serial.println(" unable to read this block");
        }
      }
    }
  }
  else{
    Serial.println("Ooops ... this doesn't seem to be a Mifare Classic card!");
  }
}

void loop(void) {
  boolean success;
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength;        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t uid2[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength2;        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)  
  // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  success = nfc.readPassiveTargetID2(PN532_MIFARE_ISO14443A, &uid[0], &uidLength, &uid2[0], &uidLength2);
  
  if (success && uidLength2>0) {
    Serial.println("--------");
    Serial.println("->Two cards detected!!!");
    Serial.println("--------");Serial.println("");
    Serial.println("First a card!");
    Serial.print("UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
    Serial.print("UID Value: ");
    for (uint8_t i=0; i < uidLength; i++) 
    {
      Serial.print(" 0x");Serial.print(uid[i], HEX); 
    }
    Serial.println("");
    Serial.println("->Trying to read the first card:");
    //nfc.inRelease(0);
    readm(uid,uidLength,1);
      Serial.println("--------");Serial.println("");
      Serial.println("Second a card!");
      Serial.print("UID Length: ");Serial.print(uidLength2, DEC);Serial.println(" bytes");
      Serial.print("UID Value: ");
      for (uint8_t i=0; i < uidLength2; i++) 
      {
        Serial.print(" 0x");Serial.print(uid2[i], HEX); 
      }
      Serial.println("");Serial.println("--------------------");Serial.println("");
      //readm(uid,uidLength,2);
  
      Serial.println("->Trying to read the second card:");
      readm(uid2,uidLength2,2);
    //}
    Serial.println("");Serial.println("--------------------");Serial.println("Done reading!");
  delay(1000);
  }
}
