section .data
;----------------------------------------------------------------------------------
; In this section I declare both the key and the msg, as well as creating variables 
; that will hold the length of the key and msg including the labels that will be 
; printed with them
;----------------------------------------------------------------------------------
  key         db 'members'
  msg         db 'pokemon'          ; 7 letter secret msg
  msg_len     equ $-msg             ; msg length

  ptxt        db 'Plain text: '
  ptxt_len    equ  $-ptxt

  msgKey      db 'Key: '
  msgKey_len  equ $-msgKey

  encTxt      db 'Encrypted text: '
  encTxt_len  equ  $-encTxt

  decTxt      db 'Decrypted text: '
  decTxt_len  equ  $-decTxt

  hexchars    db  '0123456789ABCDEF'

  nl          db 10
  filename    db 'output.txt',0


;----------------------------------------------------------------------------------
; Reserved to be used later 
;----------------------------------------------------------------------------------
section .bss
  enc         resb msg_len        ; reserve for encrypted text
  decbuf      resb msg_len        ; reserve for decrypted text
  enc_hex     resb msg_len*2

; I use this as a 256 scratch buffer, The size is not arbitrary I picked a size that 
; would ensure room to assemble all the output into one contiguous block
  buf         resb 256  

section .text
  global _start

; purpose of macro is to append len bytes from [src] to our output buffer (EDI).
; After it runs, EDI has moved to the new end which is the exact point to append next
; %1=src(pointer) | %2=#bytes to copy
; EDI will be set before calling macro this is the dest pointer in buf
; rep movsb copies ECX bytes from ESI -> EDI, which advances EDI so the next COPY
; appends directly after the last write
%macro COPY 2 
  mov esi, %1
  mov ecx, %2
  rep movsb                       ; copies ECX bytes from [ESI] -> [EDI]
%endmacro


; encryption process
;------------------------------------------------------------------------------------
_start:
  xor ecx, ecx                    ; start by clearing ecx to track index

.enCrypt:
  cmp ecx, msg_len                ; starts out as 0 when ecx is equal to we have msg
  jge .hexstart                   ; if = msg_len jmp

; parallel indexing
  mov al, [msg + ecx]             ; load plain text byte
  xor al, [key + ecx]             ; XOR with key byte
  mov [enc + ecx], al             ; store encrypted byte at same index
  inc ecx
  jmp .enCrypt
;-------------------------------------------------------------------------------------
; Hex conversion enc -> enc_hex
;-------------------------------------------------------------------------------------
.hexstart:
  xor ecx,  ecx                   ; clearing register

.hexloop:
  cmp ecx, msg_len                ; check if full msg has been convereted
  jge .decbuf                     ; if yes, jmp

  mov al, [enc + ecx]             ; al = current encrypted byte
  mov bl, al                      ; same byte well use bl for lower nibble

  shr al, 4                       ; shift right al register for high nibble
  and al, 0x0F                    ; clear high nibble
  movzx eax, al                   ; zero extend nibble to 32bit for
  mov dl, [hexchars + eax]        ; dl = ASCII hex char (high nibble)
  mov [enc_hex + ecx*2], dl       ; store at proper index*2 because hexa

  and bl, 0x0F                    ; isolate low nibble
  movzx ebx, bl                   ; zero extend into 32 bit register
  mov dl, [hexchars + ebx]        ; dl = ASCII hex char (low nibble)
  mov [enc_hex + ecx*2 + 1], dl   ; store at proper position lower nibble +1
  ; each og byte will produce two hex characters

  inc ecx
  jmp .hexloop
;--------------------------------------------------------------------------------------
.decbuf:
  xor ecx, ecx                    ; clean start for decryption process

.deCrypt:
  cmp ecx, msg_len                 ; cmp to check if we have full msg
  jge .build                       ; conditional jmp if greater than or equal
; parallel indexing
  mov al, [enc + ecx]              ; load encrypted text byte
  xor al, [key + ecx]              ; XOR with key byte (decrypt)
  mov [decbuf + ecx], al           ; store decrypted byte in decbuf at same index
  inc ecx
  jmp .deCrypt

  ; build buffer to assemble all pieces (labels, msg, key etc) into a single place 'buf'
  ; using the macro I made before so the data is contiguous 
.build: 
  cld                              ; clear directional flag
  mov   edi, buf
  
  COPY  ptxt, ptxt_len
  COPY  msg,  msg_len
  COPY  nl,   1
  
  COPY  msgKey, msgKey_len
  COPY  key,    msg_len
  COPY  nl,   1
  
  COPY  encTxt, encTxt_len
  COPY  enc_hex, msg_len*2
  COPY  nl,    1

  COPY  decTxt, decTxt_len
  COPY  decbuf, msg_len
  COPY  nl,    1

  sub   edi,  buf                   ; store length


  mov   eax,  5                     ; syscall 5 = open
  mov   ebx,  filename              ; EBX pointer to "output.txt"
  mov   ecx,  577                   ; wrOnly || create || TRUNC
  mov   esi,  420                   ; 0644 permissions
  mov   edx,  esi
  int   0x80
  mov   ebx,  eax

; write(fileDes, buf, total_len)
  mov   eax,  4
  mov   ecx,  buf
  mov   edx,  edi                   ; restore total_len
  int   0x80

; close and exit
  mov   eax,  6
  int   0x80
  mov   eax,  1
  xor   ebx,  ebx
  int   0x80  

