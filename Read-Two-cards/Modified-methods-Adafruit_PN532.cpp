/**************************************************************************/
/*!
    Waits for an ISO14443A target to enter the field

    @param  cardBaudRate  Baud rate of the card
    @param  uid           Pointer to the array that will be populated
                          with the card's UID (up to 7 bytes)
    @param  uidLength     Pointer to the variable that will hold the
                          length of the card's UID.

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
bool Adafruit_PN532::readPassiveTargetID2(uint8_t cardbaudrate, uint8_t * uid, uint8_t * uidLength, uint8_t * uid2, uint8_t * uidLength2, uint16_t timeout) {
  pn532_packetbuffer[0] = PN532_COMMAND_INLISTPASSIVETARGET;
  pn532_packetbuffer[1] = 2; // Let's have fun  
  pn532_packetbuffer[2] = cardbaudrate;

  if (!sendCommandCheckAck(pn532_packetbuffer, 3, timeout))
  {
    #ifdef PN532DEBUG
      PN532DEBUGPRINT.println(F("No card(s) read"));
    #endif
    return 0x0;  // no cards read
  }

  // wait for a card to enter the field (only possible with I2C)
  if (!_usingSPI) {
    #ifdef PN532DEBUG
      PN532DEBUGPRINT.println(F("Waiting for IRQ (indicates card presence)"));
    #endif
    if (!waitready(timeout)) {
      #ifdef PN532DEBUG
        PN532DEBUGPRINT.println(F("IRQ Timeout"));
      #endif
      return 0x0;
    }
  }

  // read data packet
  readdata(pn532_packetbuffer, 40);
  // check some basic stuff

  /* ISO14443A card response should be in the following format:

    byte            Description
    -------------   ------------------------------------------
    b0..6           Frame header and preamble
    b7              Tags Found
    b8              Tag Number (only one used in this example)
    b9..10          SENS_RES
    b11             SEL_RES
    b12             NFCID Length
    b13..NFCIDLen   NFCID                                      */
  //PN532DEBUGPRINT.println(pn532_packetbuffer[7], HEX);
  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.print(F("Found ")); PN532DEBUGPRINT.print(pn532_packetbuffer[7], DEC); PN532DEBUGPRINT.println(F(" tags"));
  #endif
  if (pn532_packetbuffer[7] != 1){
    //PN532DEBUGPRINT.print(F("More than one"));
    //return 0;
  }

  uint16_t sens_res = pn532_packetbuffer[9];
  sens_res <<= 8;
  sens_res |= pn532_packetbuffer[10];
  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.print(F("ATQA: 0x"));  PN532DEBUGPRINT.println(sens_res, HEX);
    PN532DEBUGPRINT.print(F("SAK: 0x"));  PN532DEBUGPRINT.println(pn532_packetbuffer[11], HEX);
  #endif

  /* Card appears to be Mifare Classic */
  *uidLength = pn532_packetbuffer[12];
  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.print(F("UID:"));
  #endif
  for (uint8_t i=0; i < pn532_packetbuffer[12]; i++)
  {
    uid[i] = pn532_packetbuffer[13+i];
    #ifdef MIFAREDEBUG
      PN532DEBUGPRINT.print(F(" 0x"));PN532DEBUGPRINT.print(uid[i], HEX);
    #endif
  }
  *uidLength2 = 0;
  if (pn532_packetbuffer[7] == 2){
    *uidLength2 = pn532_packetbuffer[21];
    for (uint8_t i=0; i < pn532_packetbuffer[21]; i++){
      uid2[i] = pn532_packetbuffer[22+i];
      #ifdef MIFAREDEBUG
        PN532DEBUGPRINT.print(F(" 0x"));PN532DEBUGPRINT.print(uid[i], HEX);
      #endif
    }
  }
  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.println();
  #endif

  return 1;
}
/**************************************************************************/
/*!
    Tries to authenticate a block of memory on a MIFARE card using the
    INDATAEXCHANGE command.  See section 7.3.8 of the PN532 User Manual
    for more information on sending MIFARE and other commands.

    @param  uid           Pointer to a byte array containing the card UID
    @param  uidLen        The length (in bytes) of the card's UID (Should
                          be 4 for MIFARE Classic)
    @param  blockNumber   The block number to authenticate.  (0..63 for
                          1KB cards, and 0..255 for 4KB cards).
    @param  keyNumber     Which key type to use during authentication
                          (0 = MIFARE_CMD_AUTH_A, 1 = MIFARE_CMD_AUTH_B)
    @param  keyData       Pointer to a byte array containing the 6 byte
                          key value

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t Adafruit_PN532::mifareclassic_AuthenticateBlock2 (uint8_t * uid, uint8_t uidLen, uint32_t blockNumber, uint8_t keyNumber, uint8_t * keyData, uint8_t tagActive)
{
  uint8_t len;
  uint8_t i;

  // Hang on to the key and uid data
  memcpy (_key, keyData, 6);
  memcpy (_uid, uid, uidLen);
  _uidLen = uidLen;

  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.print(F("Trying to authenticate card "));
    Adafruit_PN532::PrintHex(_uid, _uidLen);
    PN532DEBUGPRINT.print(F("Using authentication KEY "));PN532DEBUGPRINT.print(keyNumber ? 'B' : 'A');PN532DEBUGPRINT.print(F(": "));
    Adafruit_PN532::PrintHex(_key, 6);
  #endif

  // Prepare the authentication command //
  pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;   /* Data Exchange Header */
  pn532_packetbuffer[1] = tagActive;                              /* Max card numbers */
  pn532_packetbuffer[2] = (keyNumber) ? MIFARE_CMD_AUTH_B : MIFARE_CMD_AUTH_A;
  pn532_packetbuffer[3] = blockNumber;                    /* Block Number (1K = 0..63, 4K = 0..255 */
  memcpy (pn532_packetbuffer+4, _key, 6);
  for (i = 0; i < _uidLen; i++)
  {
    pn532_packetbuffer[10+i] = _uid[i];                /* 4 byte card ID */
  }

  if (! sendCommandCheckAck(pn532_packetbuffer, 10+_uidLen))
    return 0;

  // Read the response packet
  readdata(pn532_packetbuffer, 12);

  // check if the response is valid and we are authenticated???
  // for an auth success it should be bytes 5-7: 0xD5 0x41 0x00
  // Mifare auth error is technically byte 7: 0x14 but anything other and 0x00 is not good
  if (pn532_packetbuffer[7] != 0x00)
  {
    #ifdef PN532DEBUG
      PN532DEBUGPRINT.print(F("Authentification failed: "));
      Adafruit_PN532::PrintHexChar(pn532_packetbuffer, 12);
    #endif
    return 0;
  }

  return 1;
}
/**************************************************************************/
/*!
    Tries to read an entire 16-byte data block at the specified block
    address.

    @param  blockNumber   The block number to authenticate.  (0..63 for
                          1KB cards, and 0..255 for 4KB cards).
    @param  data          Pointer to the byte array that will hold the
                          retrieved data (if any)

    @returns 1 if everything executed properly, 0 for an error
*/
/**************************************************************************/
uint8_t Adafruit_PN532::mifareclassic_ReadDataBlock2 (uint8_t blockNumber, uint8_t * data, uint8_t tagActive)
{
  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.print(F("Trying to read 16 bytes from block "));PN532DEBUGPRINT.println(blockNumber);
  #endif

  /* Prepare the command */
  pn532_packetbuffer[0] = PN532_COMMAND_INDATAEXCHANGE;
  pn532_packetbuffer[1] = tagActive;                      /* Card number */
  pn532_packetbuffer[2] = MIFARE_CMD_READ;        /* Mifare Read command = 0x30 */
  pn532_packetbuffer[3] = blockNumber;            /* Block Number (0..63 for 1K, 0..255 for 4K) */

  /* Send the command */
  if (! sendCommandCheckAck(pn532_packetbuffer, 4))
  {
    #ifdef MIFAREDEBUG
      PN532DEBUGPRINT.println(F("Failed to receive ACK for read command"));
    #endif
    return 0;
  }

  /* Read the response packet */
  readdata(pn532_packetbuffer, 26);

  /* If byte 8 isn't 0x00 we probably have an error */
  if (pn532_packetbuffer[7] != 0x00)
  {
    #ifdef MIFAREDEBUG
      PN532DEBUGPRINT.println(F("Unexpected response"));
      Adafruit_PN532::PrintHexChar(pn532_packetbuffer, 26);
    #endif
    return 0;
  }

  /* Copy the 16 data bytes to the output buffer        */
  /* Block content starts at byte 9 of a valid response */
  memcpy (data, pn532_packetbuffer+8, 16);

  /* Display data for debug if requested */
  #ifdef MIFAREDEBUG
    PN532DEBUGPRINT.print(F("Block "));
    PN532DEBUGPRINT.println(blockNumber);
    Adafruit_PN532::PrintHexChar(data, 16);
  #endif

  return 1;
}
