CREATE OR REPLACE PACKAGE SHA256 IS
/*
    Oracle PL/SQL Package to compute SHA256 message digest of files or memory blocks.
    according to the definition of SHA256 in FIPS 180-2.

    Copyright (C) 2014, Steve Jang <cruiserx@hanmail.net>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

    -- type declarations
    TYPE ta_number IS TABLE OF NUMBER INDEX BY binary_integer;

    TYPE tr_ctx IS RECORD (
        H     TA_NUMBER, --//8
        total TA_NUMBER, --//2
        buflen NUMBER,
        buffer32 TA_NUMBER  --//32
    );

    -- constant declarations
    /* Constant for 32bit bitwise operations */
    fullbits NUMBER := to_number('FFFFFFFF','xxxxxxxx');
    bits_FF000000 NUMBER := to_number('FF000000','xxxxxxxx');
    bits_00FF0000 NUMBER := to_number('00FF0000','xxxxxxxx');
    bits_0000FF00 NUMBER := to_number('0000FF00','xxxxxxxx');
    bits_000000FF NUMBER := to_number('000000FF','xxxxxxxx');
    bits_00FFFFFF NUMBER := to_number('00FFFFFF','xxxxxxxx');
    bits_FF00FFFF NUMBER := to_number('FF00FFFF','xxxxxxxx');
    bits_FFFF00FF NUMBER := to_number('FFFF00FF','xxxxxxxx');
    bits_FFFFFF00 NUMBER := to_number('FFFFFF00','xxxxxxxx');
    bits_FFFF0000 NUMBER := to_number('FFFF0000','xxxxxxxx');
    bits_80000000 NUMBER := to_number('80000000','xxxxxxxx');
    bits_00800000 NUMBER := to_number('00800000','xxxxxxxx');
    bits_00008000 NUMBER := to_number('00008000','xxxxxxxx');
    bits_00000080 NUMBER := to_number('00000080','xxxxxxxx');
    bits_FFFFFFC0 NUMBER := to_number('FFFFFFC0','xxxxxxxx');

    /* This array contains the bytes used to pad the buffer to the next
       64-byte boundary.  (FIPS 180-2:5.1.1)  */
    fillbuf TA_NUMBER; --//16 { 0x80, 0 /* , 0, 0, ...  */ };

    /* Constants for SHA256 from FIPS 180-2:4.2.2.  */
    K TA_NUMBER; --//64 {...}



    -- Public function and procedure declarations

    /* Initialize structure containing state of computation.
       (FIPS 180-2: 5.3.2)  */
    PROCEDURE sha256_init_ctx (ctx IN OUT NOCOPY TR_CTX);

    /* Starting with the result of former calls of this function (or the
       initialization function update the context for the next LEN bytes
       starting at BUFFER.
       It is NOT required that LEN is a multiple of 64.  */
    PROCEDURE sha256_process_bytes (buffer IN RAW,
                                      len IN NUMBER,
                                      ctx IN OUT NOCOPY TR_CTX);


    /* Process LEN bytes of BUFFER, accumulating context into CTX.
       It is assumed that LEN % 64 == 0.  */
    PROCEDURE sha256_process_block (buffer IN TA_NUMBER,
                                    len IN NUMBER,
                                    ctx IN OUT NOCOPY TR_CTX);


    /* Process the remaining bytes in the buffer and put result from CTX
       in first 32 bytes following RESBUF.

       IMPORTANT: On some systems it is required that RESBUF is correctly
       aligned for a 32 bits value.  */
    PROCEDURE sha256_finish_ctx (ctx IN OUT NOCOPY TR_CTX,
                                   resbuf OUT NOCOPY TA_NUMBER);

    FUNCTION BITOR (x IN NUMBER, y IN NUMBER) RETURN NUMBER;
    FUNCTION BITXOR (x IN NUMBER, y IN NUMBER) RETURN NUMBER;
    FUNCTION BITNOT (x IN NUMBER) RETURN NUMBER;

    FUNCTION LEFTSHIFT( x IN NUMBER, y IN NUMBER) RETURN NUMBER;
    FUNCTION RIGHTSHIFT( x IN NUMBER, y IN NUMBER) RETURN NUMBER;
    FUNCTION CYCLIC( x IN NUMBER, y IN NUMBER) RETURN NUMBER;

    /* Operators defined in FIPS 180-2:4.1.2.  */
    FUNCTION OP_Ch(x IN NUMBER, y IN NUMBER, z IN NUMBER) RETURN NUMBER;
    FUNCTION OP_Maj(x IN NUMBER, y IN NUMBER, z IN NUMBER) RETURN NUMBER;
    FUNCTION OP_S0(x IN NUMBER) RETURN NUMBER;
    FUNCTION OP_S1(x IN NUMBER) RETURN NUMBER;
    FUNCTION OP_R0(x IN NUMBER) RETURN NUMBER;
    FUNCTION OP_R1(x IN NUMBER) RETURN NUMBER;

    /* Final Function */
    FUNCTION ENCRYPT(x IN VARCHAR2) RETURN VARCHAR2;
    FUNCTION ENCRYPT_RAW(x IN RAW) RETURN VARCHAR2;

END SHA256;
/
