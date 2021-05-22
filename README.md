# vm_entry - an entry point into the vm

`vm_entry` is the code name for the vmp2 routine which is used to transition control flow from non-virtualized code to virtualized code. Prior to calling this function a value is pushed onto the stack.

#### encrypted opcode rva

```nasm
push    0xFFFFFFFF890001FA
jmp     vm_entry
```

The value pushed onto the stack is an encrypted RVA to the vm instructions to execute. As you can see below, the value is decrypted inside of the `vm_entry` function and is loaded into RSI. The decryption is unique per-build, however it seems that there is only three transformations done, no more, no less.

#### decrypt opcode rva

```nasm
; pushed value on stack (0xFFFFFFFF890001FA)
mov     esi, [rsp+0xA0]

; unique, per-build, decryption. there seems to obly be 3 of these.
not     esi
neg     esi
ror     esi, 0x1A

; vmp2 image base address is always 0x14000000... 
mov     rax, 0x100000000 
add     rsi, rax

; add module base
add     rsi, [rbp+0]
```

If you decrypt the encrypted stack value, you end up with `0x140007EE2`. This is the image based address of the virtual instructions which will be executed by the vm. These virtual instructions are encrypted. I talk more about those in the `virtual instructions` section of the readme.

### calc_jmp - transition from one vm handler to another

`calc_jmp` is a part of the `vm_entry` routine. vm handler jmp's to this section of code in order to calculate the address of the next vm handler. This code decrypts the first opcode of the next virtual instruction, advances vip, obtains and decrypts the next vm handler's linear virtual address, and finally jmps to it. `AL` contains the index into the vm handler table after the jmp, and `BL` contains the decryption key for the first opcode. `BL` is then used by vm handlers to decrypt immediate values.

```nasm
; get the first opcode of the next virtual instruction
mov     al, [rsi]

; this is in every single vmp2 binary... 
; BL contains a "rolling" encryption key... 
xor     al, bl

; again, three unique transformations...
neg     al
rol     al, 5
inc     al

; this is in every single vmp2 binary...
; BL is a "rolling" encryption key...
; it gets updated here...
xor     bl, al

; index into the vm handler table...
movzx   rax, al
mov     rdx, [r12+rax*8]

; decrypt the vm handler rva...
xor     rdx, 7F3D2149h

; advance the virtual instruction pointer (++VIP)
inc     rsi

; jmp to next vm handler
add     rdx, r13
jmp     rdx
```

# virtual instructions - opcode's, vm handler index, and immediate values

virtual instructions are per-build encrypted RISC based instructions. They consist of an encrypted vm handler index, and optionally an encrypted immediate value. They are located inside of `.vmp` and `.text` sections. When execution of opcodes is desired, a push of an encrypted rva to these opcodes is done. Sadly, the rva is only 32bit's so you cannot easily run your own sequence of vm handlers. I suppose you could but you would need to be near the vmp'ed module in memory.

```
[vm handler index][immediate value up to 8 bytes]
```

*note that the vm handler index and immediate values are all encrypted*

#### opcode encryption

each opcode of a virtual instruction is encrypted by itself. 

##### first opcode - vm handler index

```nasm
; note trans is short for transformation...
; this includes: xor, neg, not, nor, add, sub, etc

mov al, [rsi]   ; RSI is VIP...
                ; BL is the byte address of the encrypted opcode...
                ; (only for the first decryption of the first opcode....)
trans al, bl    ; AL is the encrypted opcode...

; note that there is ALWAYS three transformations...
trans al
trans al
trans al


trans bl, al    ; at this point AL contains the decrypted opcode 
                ; (which is the vm handler index)...
                ; BL now can decrypt the next opcode...
                ; also note that the transformation done to BL is also done to AL...
```

*first opcode decryption of the first virtual instruction*


```nasm
mov al, [rsi]   ; RSI is VIP...
trans al, bl    ; AL is the encrypted opcode...

; note that there is ALWAYS three transformations...
trans al
trans al
trans al

trans bl, al    ; BL contains the decrypt key from the last virtual instruction... 
                ; read the assembly above at this instruction for BL...
```

*first opcode decryption of the second virtual instruction*

##### second opcode - immediate values

Each virtual instruction can have a second opcode. This second opcode is decrypted by the "rolling" decryption key stored in `BL`. An example of a second opcode would be the first virtual instruction always executed. 

```nasm
movzx   eax, byte ptr [rsi]

; transformations done by vm handlers on immediate values are unique... 
; unlike the `calc_jmp` block of code which vm handlers use to get to the next virtual instruction...
sub     al, bl

; again, three unique transformations done on AL...
ror     al, 2
not     al
inc     al

; the same transformation done al AL is then done on BL with the decrypted opcode...
sub     bl, al

; this is some sort of VPOP and store instruction where a value comes off the virtual stack and into a place in RDI
; RDI seems to be scratch space, heap, or a per-binary virtual register mapping, not sure yet.
mov     rdx, [rbp+0]
add     rbp, 8
mov     [rax+rdi], rdx
```