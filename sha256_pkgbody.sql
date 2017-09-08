CREATE OR REPLACE PACKAGE BODY SHA256 IS
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

    FUNCTION BITOR (x IN NUMBER, y IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN (x + y - BITAND(x, y));
    END;

    FUNCTION BITXOR (x IN NUMBER, y IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN (BITOR(x, y) - BITAND(x, y));
    END;
    FUNCTION BITNOT (x IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN (fullbits - x);
    END;

    FUNCTION LEFTSHIFT( x IN NUMBER, y IN NUMBER) RETURN NUMBER AS
        tmp NUMBER := x;
    BEGIN
        FOR idx IN 1..y LOOP
            tmp := tmp * 2;
        END LOOP;
        RETURN BITAND(tmp, fullbits);
    END;
    FUNCTION RIGHTSHIFT( x IN NUMBER, y IN NUMBER) RETURN NUMBER AS
        tmp NUMBER := x;
    BEGIN
        FOR idx IN 1..y LOOP
            tmp := trunc(tmp / 2);
        END LOOP;
        RETURN BITAND(tmp, fullbits);
    END;
    FUNCTION CYCLIC( x IN NUMBER, y IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITOR(
            RIGHTSHIFT(x, y),
            LEFTSHIFT(x, 32-y)
        );
    END;

    /* Operators defined in FIPS 180-2:4.1.2.  */
    FUNCTION OP_Ch(x IN NUMBER, y IN NUMBER, z IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITXOR(
                 BITAND(x, y),
                 BITAND(BITNOT(x), z)
               );
    END;

    FUNCTION OP_Maj(x IN NUMBER, y IN NUMBER, z IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITXOR(
                  BITXOR(
                     BITAND(x,y),
                     BITAND(x,z)
                  ),
                  BITAND(y,z)
               );
    END;

    FUNCTION OP_S0(x IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITXOR(
                  BITXOR(
                     CYCLIC(x,2),
                     CYCLIC(x,13)
                  ),
                  CYCLIC(x,22)
               );
    END;

    FUNCTION OP_S1(x IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITXOR(
                  BITXOR(
                     CYCLIC(x, 6),
                     CYCLIC(x, 11)
                  ),
                  CYCLIC(x, 25)
               );
    END;

    FUNCTION OP_R0(x IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITXOR(
                  BITXOR(
                     CYCLIC(x, 7),
                     CYCLIC(x, 18)
                  ),
                  RIGHTSHIFT(x, 3)
               );
    END;

    FUNCTION OP_R1(x IN NUMBER) RETURN NUMBER AS
    BEGIN
        RETURN BITXOR(
                  BITXOR(
                     CYCLIC(x, 17),
                     CYCLIC(x, 19)
                  ),
                  RIGHTSHIFT(x, 10)
               );
    END;


    /* Initialize structure containing state of computation.
       (FIPS 180-2: 5.3.2)  */
    PROCEDURE sha256_init_ctx (ctx IN OUT NOCOPY TR_CTX)
    IS
    BEGIN
        ctx.H(0) := to_number('6a09e667', 'xxxxxxxx');
        ctx.H(1) := to_number('bb67ae85', 'xxxxxxxx');
        ctx.H(2) := to_number('3c6ef372', 'xxxxxxxx');
        ctx.H(3) := to_number('a54ff53a', 'xxxxxxxx');
        ctx.H(4) := to_number('510e527f', 'xxxxxxxx');
        ctx.H(5) := to_number('9b05688c', 'xxxxxxxx');
        ctx.H(6) := to_number('1f83d9ab', 'xxxxxxxx');
        ctx.H(7) := to_number('5be0cd19', 'xxxxxxxx');
        ctx.total(0) := 0;
        ctx.total(1) := 0;
        ctx.buflen := 0;
        FOR idx IN 0..32 LOOP
            ctx.buffer32(idx) := 0;
        END LOOP;

    END;

    /* Process LEN bytes of BUFFER, accumulating context into CTX.
       It is assumed that LEN % 64 == 0.  */
    procedure sha256_process_block (buffer IN TA_NUMBER,
                                    len IN NUMBER,
                                    ctx IN OUT NOCOPY TR_CTX)
    IS
        words TA_NUMBER := buffer;
        nwords NUMBER := trunc(len / 4);
        pos_words NUMBER;

        t NUMBER;
        a NUMBER := ctx.H(0);
        b NUMBER := ctx.H(1);
        c NUMBER := ctx.H(2);
        d NUMBER := ctx.H(3);
        e NUMBER := ctx.H(4);
        f NUMBER := ctx.H(5);
        g NUMBER := ctx.H(6);
        h NUMBER := ctx.H(7);

        W TA_NUMBER; --//[64] ;
        a_save NUMBER;
        b_save NUMBER;
        c_save NUMBER;
        d_save NUMBER;
        e_save NUMBER;
        f_save NUMBER;
        g_save NUMBER;
        h_save NUMBER;

        T1 NUMBER;
        T2 NUMBER;

    BEGIN

        /* First increment the byte count.  FIPS 180-2 specifies the possible
         length of the file up to 2^64 bits.  Here we only compute the
         number of bytes.  */
        ctx.total(1) := ctx.total(1) + len;

        /* Process all bytes in the buffer with 64 bytes in each round of
         the loop.  */
        pos_words := 0;
        WHILE (nwords > 0)
        LOOP
            a_save := a;
            b_save := b;
            c_save := c;
            d_save := d;
            e_save := e;
            f_save := f;
            g_save := g;
            h_save := h;

            /* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
            FOR t IN 0..15 LOOP
                W(t) := words(pos_words);
                pos_words := pos_words + 1;
            END LOOP;

            FOR t IN 16..63 LOOP
                W(t) := BITAND(OP_R1(W(t-2)) + W(t-7) + OP_R0(W(t-15)) + W(t-16), fullbits);
            END LOOP;

            /* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
            FOR t IN 0..63 LOOP
                T1 := BITAND(h + OP_S1(e) + OP_Ch (e, f, g) + K(t) + W(t), fullbits);
                T2 := BITAND(OP_S0(a) + OP_Maj (a, b, c), fullbits);
                h := g;
                g := f;
                f := e;
                e := BITAND(d + T1, fullbits);
                d := c;
                c := b;
                b := a;
                a := BITAND(T1 + T2, fullbits);
            END LOOP;

            /* Add the starting values of the context according to FIPS 180-2:6.2.2 step 4.  */
            a := BITAND(a + a_save, fullbits);
            b := BITAND(b + b_save, fullbits);
            c := BITAND(c + c_save, fullbits);
            d := BITAND(d + d_save, fullbits);
            e := BITAND(e + e_save, fullbits);
            f := BITAND(f + f_save, fullbits);
            g := BITAND(g + g_save, fullbits);
            h := BITAND(h + h_save, fullbits);

            /* Prepare for the next round.  */
            nwords := nwords - 16;

        END LOOP;

        /* Put checksum in context given as argument.  */
        ctx.H(0) := a;
        ctx.H(1) := b;
        ctx.H(2) := c;
        ctx.H(3) := d;
        ctx.H(4) := e;
        ctx.H(5) := f;
        ctx.H(6) := g;
        ctx.H(7) := h;

    END;


    /* Starting with the result of former calls of this function (or the
       initialization function update the context for the next LEN bytes
       starting at BUFFER.
       It is NOT required that LEN is a multiple of 64.  */
    PROCEDURE sha256_process_bytes (buffer IN RAW,
                                      len IN NUMBER,
                                      ctx IN OUT NOCOPY TR_CTX)
    IS
        left_over NUMBER;
        left_over_blk NUMBER;
        left_over_mod NUMBER;
        add NUMBER;
        t_len NUMBER := len;
        t_buffer RAW(32767) := buffer;
        x_buffer32 TA_NUMBER;

    BEGIN
        /* When we already have some bits in our internal buffer concatenate
         both inputs first.  */
        IF (ctx.buflen > 0) THEN

            left_over := ctx.buflen;
            add := CASE WHEN 128 - left_over > t_len THEN t_len ELSE 128 - left_over END;

            FOR idx IN 1..add LOOP
                left_over_blk := trunc((left_over+idx-1)/4);
                left_over_mod := mod((left_over+idx-1), 4);

                IF (left_over_mod=0) THEN
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_00FFFFFF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*16777216;
                ELSIF (left_over_mod=1) THEN
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_FF00FFFF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*65536;
                ELSIF (left_over_mod=2) THEN
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_FFFF00FF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*256;
                ELSE
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_FFFFFF00) + to_number(utl_raw.substr(t_buffer,idx,1),'0x');
                END IF;
            END LOOP;

            ctx.buflen := ctx.buflen + add;

            IF (ctx.buflen > 64) THEN
                sha256_process_block (ctx.buffer32, BITAND(ctx.buflen, bits_FFFFFFC0), ctx);

                ctx.buflen := BITAND(ctx.buflen, 63);

                /* The regions in the following copy operation cannot overlap.  */
                /* memcpy (ctx->buffer, & ctx->buffer[(left_over + add) & ~63], ctx->buflen); */
                FOR idx IN 1..ctx.buflen LOOP
                    DECLARE
                        dest_pos NUMBER := idx-1;
                        dest_pos_blk NUMBER := trunc(dest_pos/4);
                        dest_pos_mod NUMBER := mod(dest_pos, 4);
                        src_pos NUMBER := BITAND(left_over + add, bits_FFFFFFC0)+idx-1;
                        src_pos_blk NUMBER := trunc(src_pos/4);
                        src_pos_mod NUMBER := mod(src_pos, 4);
                        byte_value NUMBER;
                    BEGIN

                        IF (src_pos_mod=0) THEN
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_FF000000)/16777216;
                        ELSIF (src_pos_mod=1) THEN
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_00FF0000)/65536;
                        ELSIF (src_pos_mod=2) THEN
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_0000FF00)/256;
                        ELSE
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_000000FF);
                        END IF;

                        IF (dest_pos_mod=0) THEN
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_00FFFFFF) + byte_value*16777216;
                        ELSIF (dest_pos_mod=1) THEN
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_FF00FFFF) + byte_value*65536;
                        ELSIF (dest_pos_mod=2) THEN
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_FFFF00FF) + byte_value*256;
                        ELSE
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_FFFFFF00) + byte_value;
                        END IF;
                    END;

                END LOOP;
            END IF;

            t_buffer := utl_raw.substr(t_buffer, add+1);
            t_len := t_len - add;
        END IF;

        /* Process available complete blocks.  */
        IF (t_len >= 64) THEN

            DECLARE
                cnt NUMBER := BITAND(t_len, bits_FFFFFFC0);
                target_blk NUMBER;
                target_mod NUMBER;
            BEGIN
                FOR idx IN 0..cnt LOOP
                    x_buffer32(idx) := 0;
                END LOOP;

                FOR idx IN 1..cnt LOOP
                    target_blk := trunc((idx-1)/4);
                    target_mod := mod((idx-1), 4);

                    IF (target_mod=0) THEN
                        x_buffer32(target_blk) := BITAND(x_buffer32(target_blk),bits_00FFFFFF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*16777216;
                    ELSIF (target_mod=1) THEN
                        x_buffer32(target_blk) := BITAND(x_buffer32(target_blk),bits_FF00FFFF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*65536;
                    ELSIF (target_mod=2) THEN
                        x_buffer32(target_blk) := BITAND(x_buffer32(target_blk),bits_FFFF00FF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*256;
                    ELSE
                        x_buffer32(target_blk) := BITAND(x_buffer32(target_blk),bits_FFFFFF00) + to_number(utl_raw.substr(t_buffer,idx,1),'0x');
                    END IF;
                END LOOP;
                sha256_process_block (x_buffer32, cnt, ctx);
                IF (utl_raw.length(t_buffer) <= cnt) THEN
                	t_buffer := '';
                ELSE
	                t_buffer := utl_raw.substr(t_buffer, cnt+1);
                END IF;
            END;

            t_len := BITAND(t_len, 63);
        END IF;



        /* Move remaining bytes into internal buffer.  */
        IF (t_len > 0) THEN

            left_over := ctx.buflen;

            /* memcpy (& ctx->buffer[left_over], t_buffer, t_len); */
            FOR idx IN 1..t_len LOOP
                left_over_blk := trunc((left_over+idx-1)/4);
                left_over_mod := mod((left_over+idx-1), 4);

                IF (left_over_mod=0) THEN
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_00FFFFFF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*16777216;
                ELSIF (left_over_mod=1) THEN
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_FF00FFFF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*65536;
                ELSIF (left_over_mod=2) THEN
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_FFFF00FF) + to_number(utl_raw.substr(t_buffer,idx,1),'0x')*256;
                ELSE
                    ctx.buffer32(left_over_blk) := BITAND(ctx.buffer32(left_over_blk),bits_FFFFFF00) + to_number(utl_raw.substr(t_buffer,idx,1),'0x');
                END IF;
            END LOOP;

            left_over := left_over + t_len;

            IF (left_over >= 64) THEN

                sha256_process_block (ctx.buffer32, 64, ctx);
                left_over := left_over - 64;

                /* memcpy (ctx->buffer, & ctx->buffer[64], left_over); */
                FOR idx IN 1..left_over LOOP
                    DECLARE
                        dest_pos NUMBER := idx-1;
                        dest_pos_blk NUMBER := trunc(dest_pos/4);
                        dest_pos_mod NUMBER := mod(dest_pos, 4);
                        src_pos NUMBER := idx+64-1;
                        src_pos_blk NUMBER := trunc(src_pos/4);
                        src_pos_mod NUMBER := mod(src_pos, 4);
                        byte_value NUMBER;
                    BEGIN

                        IF (src_pos_mod=0) THEN
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_FF000000)/16777216;
                        ELSIF (src_pos_mod=1) THEN
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_00FF0000)/65536;
                        ELSIF (src_pos_mod=2) THEN
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_0000FF00)/256;
                        ELSE
                            byte_value := BITAND(ctx.buffer32(src_pos_blk),bits_000000FF);
                        END IF;

                        IF (dest_pos_mod=0) THEN
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_00FFFFFF) + byte_value*16777216;
                        ELSIF (dest_pos_mod=1) THEN
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_FF00FFFF) + byte_value*65536;
                        ELSIF (dest_pos_mod=2) THEN
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_FFFF00FF) + byte_value*256;
                        ELSE
                            ctx.buffer32(dest_pos_blk) := BITAND(ctx.buffer32(dest_pos_blk),bits_FFFFFF00) + byte_value;
                        END IF;
                    END;

                END LOOP;

            END IF;
            ctx.buflen := left_over;
        END IF;
    END;

    /* Process the remaining bytes in the buffer and put result from CTX
       in first 32 bytes following RESBUF.

       IMPORTANT: On some systems it is required that RESBUF is correctly
       aligned for a 32 bits value.  */
    PROCEDURE sha256_finish_ctx (ctx IN OUT NOCOPY TR_CTX,
                                   resbuf OUT NOCOPY TA_NUMBER)
    IS
        bytes NUMBER := ctx.buflen;
        pad NUMBER;
        pad_in NUMBER;
        pad_out NUMBER;
        start_idx NUMBER;
        i NUMBER;
    BEGIN
        /* Now count remaining bytes.  */
        ctx.total(1) := ctx.total(1)+bytes;

        /* Fill left bytes. */
        IF (bytes >= 56) THEN
            pad := 64 + 56 - bytes;
        ELSE
            pad := 56 - bytes;
        END IF;
        pad_in := 4 - MOD(bytes,4);
        pad_out := pad - pad_in;
        start_idx := (bytes-MOD(bytes,4))/4;
        IF (pad_in < 4) THEN
            IF (pad_in = 1) THEN
                ctx.buffer32(start_idx) := BITAND(ctx.buffer32(start_idx), bits_FFFFFF00) + bits_00000080;
            ELSIF (pad_in = 2) THEN
                ctx.buffer32(start_idx) := BITAND(ctx.buffer32(start_idx), bits_FFFF0000) + bits_00008000;
            ELSIF (pad_in = 3) THEN
                ctx.buffer32(start_idx) := BITAND(ctx.buffer32(start_idx), bits_FF000000) + bits_00800000;
            END IF;

            FOR idx IN (start_idx+1)..(start_idx+1+pad_out/4-1) LOOP
                ctx.buffer32(idx) := 0;
            END LOOP;
        ELSE
            FOR idx IN start_idx..(start_idx+pad/4-1) LOOP
                IF (idx = start_idx) THEN
                    ctx.buffer32(idx) := bits_80000000;
                ELSE
                    ctx.buffer32(idx) := 0;
                END IF;
            END LOOP;
        END IF;


        /* Put the 64-bit file length in *bits* at the end of the buffer.  */
        ctx.buffer32((bytes + pad + 4) / 4) :=  BITAND(ctx.total(1) * 8, fullbits);
        ctx.buffer32((bytes + pad) / 4) :=
            BITOR (
                BITAND(ctx.total(0) * 8, fullbits),
                BITAND(ctx.total(1) / 536870912, fullbits)
            );

        sha256_process_block (ctx.buffer32, bytes + pad + 8, ctx);

        FOR idx IN 0..7 LOOP
            resbuf(idx) := ctx.H(idx);
        END LOOP;
    END;

    FUNCTION ENCRYPT(x IN VARCHAR2) RETURN VARCHAR2 AS
        ctx TR_CTX;
        res TA_NUMBER;
    BEGIN
        RETURN ENCRYPT_RAW(utl_raw.cast_to_raw(x));
    END;

    FUNCTION ENCRYPT_RAW(x IN RAW) RETURN VARCHAR2 AS
        ctx TR_CTX;
        res TA_NUMBER;
    BEGIN
        sha256_init_ctx (ctx);

        sha256_process_bytes(x, utl_raw.length(x), ctx);

        sha256_finish_ctx(ctx, res);

        RETURN
            to_char(res(0),'FM0xxxxxxx') ||
            to_char(res(1),'FM0xxxxxxx') ||
            to_char(res(2),'FM0xxxxxxx') ||
            to_char(res(3),'FM0xxxxxxx') ||
            to_char(res(4),'FM0xxxxxxx') ||
            to_char(res(5),'FM0xxxxxxx') ||
            to_char(res(6),'FM0xxxxxxx') ||
            to_char(res(7),'FM0xxxxxxx');
    END;

BEGIN
    -- Fill Buffer Initialization
    fillbuf(0) := bits_80000000;
    for i in 1..7 loop
        fillbuf(i) := 0;
    end loop;

    -- K Value Initialization
    K(0) := to_number('428a2f98', 'xxxxxxxx');
    K(1) := to_number('71374491', 'xxxxxxxx');
    K(2) := to_number('b5c0fbcf', 'xxxxxxxx');
    K(3) := to_number('e9b5dba5', 'xxxxxxxx');
    K(4) := to_number('3956c25b', 'xxxxxxxx');
    K(5) := to_number('59f111f1', 'xxxxxxxx');
    K(6) := to_number('923f82a4', 'xxxxxxxx');
    K(7) := to_number('ab1c5ed5', 'xxxxxxxx');
    K(8) := to_number('d807aa98', 'xxxxxxxx');
    K(9) := to_number('12835b01', 'xxxxxxxx');
    K(10) := to_number('243185be', 'xxxxxxxx');
    K(11) := to_number('550c7dc3', 'xxxxxxxx');
    K(12) := to_number('72be5d74', 'xxxxxxxx');
    K(13) := to_number('80deb1fe', 'xxxxxxxx');
    K(14) := to_number('9bdc06a7', 'xxxxxxxx');
    K(15) := to_number('c19bf174', 'xxxxxxxx');
    K(16) := to_number('e49b69c1', 'xxxxxxxx');
    K(17) := to_number('efbe4786', 'xxxxxxxx');
    K(18) := to_number('0fc19dc6', 'xxxxxxxx');
    K(19) := to_number('240ca1cc', 'xxxxxxxx');
    K(20) := to_number('2de92c6f', 'xxxxxxxx');
    K(21) := to_number('4a7484aa', 'xxxxxxxx');
    K(22) := to_number('5cb0a9dc', 'xxxxxxxx');
    K(23) := to_number('76f988da', 'xxxxxxxx');
    K(24) := to_number('983e5152', 'xxxxxxxx');
    K(25) := to_number('a831c66d', 'xxxxxxxx');
    K(26) := to_number('b00327c8', 'xxxxxxxx');
    K(27) := to_number('bf597fc7', 'xxxxxxxx');
    K(28) := to_number('c6e00bf3', 'xxxxxxxx');
    K(29) := to_number('d5a79147', 'xxxxxxxx');
    K(30) := to_number('06ca6351', 'xxxxxxxx');
    K(31) := to_number('14292967', 'xxxxxxxx');
    K(32) := to_number('27b70a85', 'xxxxxxxx');
    K(33) := to_number('2e1b2138', 'xxxxxxxx');
    K(34) := to_number('4d2c6dfc', 'xxxxxxxx');
    K(35) := to_number('53380d13', 'xxxxxxxx');
    K(36) := to_number('650a7354', 'xxxxxxxx');
    K(37) := to_number('766a0abb', 'xxxxxxxx');
    K(38) := to_number('81c2c92e', 'xxxxxxxx');
    K(39) := to_number('92722c85', 'xxxxxxxx');
    K(40) := to_number('a2bfe8a1', 'xxxxxxxx');
    K(41) := to_number('a81a664b', 'xxxxxxxx');
    K(42) := to_number('c24b8b70', 'xxxxxxxx');
    K(43) := to_number('c76c51a3', 'xxxxxxxx');
    K(44) := to_number('d192e819', 'xxxxxxxx');
    K(45) := to_number('d6990624', 'xxxxxxxx');
    K(46) := to_number('f40e3585', 'xxxxxxxx');
    K(47) := to_number('106aa070', 'xxxxxxxx');
    K(48) := to_number('19a4c116', 'xxxxxxxx');
    K(49) := to_number('1e376c08', 'xxxxxxxx');
    K(50) := to_number('2748774c', 'xxxxxxxx');
    K(51) := to_number('34b0bcb5', 'xxxxxxxx');
    K(52) := to_number('391c0cb3', 'xxxxxxxx');
    K(53) := to_number('4ed8aa4a', 'xxxxxxxx');
    K(54) := to_number('5b9cca4f', 'xxxxxxxx');
    K(55) := to_number('682e6ff3', 'xxxxxxxx');
    K(56) := to_number('748f82ee', 'xxxxxxxx');
    K(57) := to_number('78a5636f', 'xxxxxxxx');
    K(58) := to_number('84c87814', 'xxxxxxxx');
    K(59) := to_number('8cc70208', 'xxxxxxxx');
    K(60) := to_number('90befffa', 'xxxxxxxx');
    K(61) := to_number('a4506ceb', 'xxxxxxxx');
    K(62) := to_number('bef9a3f7', 'xxxxxxxx');
    K(63) := to_number('c67178f2', 'xxxxxxxx');

END SHA256;
/
