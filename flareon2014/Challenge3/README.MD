# Challenge 3

We are given a small binary `such_evil`. Analyzing the binary, the first suspicious thing we see is that it doesn't have many imports, which means a) its functionality relatively limited or b) it is a packed program, or both. We can see the imports below (from LordPE):

```
->Import Table
   1. ImageImportDescriptor:
    OriginalFirstThunk:  0x00003048
    TimeDateStamp:       0x00000000  (GMT: Thu Jan 01 00:00:00 1970)
    ForwarderChain:      0x00000000
    Name:                0x00003068  ("msvcrt.dll")
    FirstThunk:          0x00003028

    Ordinal/Hint API name
    ------------ ---------------------------------------
    0x0000       "_controlfp"
    0x0000       "__set_app_type"
    0x0000       "__getmainargs"
    0x0000       "exit"
    0x0000       "_XcptFilter"
    0x0000       "_exit"
    0x0000       "_except_handler3"
```

Running the binary, we see that it crashes with a BrokenByte, which is highly suspicious and probably indicative of unpacking.
Opening the program in IDA, we see a suspicious function at `0x401000`:
```
.text:00401000 push    ebp
.text:00401001 mov     ebp, esp
.text:00401003 sub     esp, 204h
.text:00401009 nop
.text:0040100A mov     eax, 0E8h
.text:0040100F mov     [ebp+var_201], al
.text:00401015 mov     eax, 0
.text:0040101A mov     [ebp+var_200], al
.text:00401020 mov     eax, 0
.text:00401025 mov     [ebp+var_1FF], al
.text:0040102B mov     eax, 0
.text:00401030 mov     [ebp+var_1FE], al
.text:00401036 mov     eax, 0
.text:0040103B mov     [ebp+var_1FD], al
.text:00401041 mov     eax, 8Bh
.text:00401046 mov     [ebp+var_1FC], al
.text:0040104C mov     eax, 34h
.text:00401051 mov     [ebp+var_1FB], al
.text:00401057 mov     eax, 24h
.text:0040105C mov     [ebp+var_1FA], al
.text:00401062 mov     eax, 83h
.text:00401067 mov     [ebp+var_1F9], al
.text:0040106D mov     eax, 0C6h
.text:00401072 mov     [ebp+var_1F8], al
.text:00401078 mov     eax, 1Ch
.text:0040107D mov     [ebp+var_1F7], al
...
.text:00402492 mov     [ebp+var_1], al
.text:00402495 lea     eax, [ebp+var_201]
.text:0040249B call    eax
```

The binary loads 0x201 bytes of shellcode onto the stack, loads the address into eax, and calls the address. Following `eax`, we see the following shellcode being executed:

```
debug007:0019FD4F loc_19FD4F:                             ; CODE XREF: debug007:0019FD59↓j
debug007:0019FD4F cmp     ecx, 0
debug007:0019FD52 jz      short loc_19FD5B
debug007:0019FD54 xor     byte ptr [esi], 66h
debug007:0019FD57 inc     esi
debug007:0019FD58 dec     ecx
debug007:0019FD59 jmp     short loc_19FD4F
debug007:0019FD5B ; ---------------------------------------------------------------------------
debug007:0019FD5B
debug007:0019FD5B loc_19FD5B:                             ; CODE XREF: debug007:0019FD52↑j
debug007:0019FD5B jmp     loc_19FD70
```

The binary decrypts some portion of its own code using XOR cipher, as seen above, and then jumps to the next section of the code. This repeats for some number of times. We simply step through while scanning if the string `flare-on` exists in memory (I did this manually, but it can be automatic through IDA scripting, but it wasn't necessary since the program was small). Eventually, the flag pops up in view in our hexdump:

```
0019FE60  43 46 EB EB E9 1D 00 00  00 73 75 63 68 2E 35 68  CFëëé....such.5h
0019FE70  33 31 31 30 31 30 31 30  31 40 66 6C 61 72 65 2D  311010101@flare-
0019FE80  6F 6E 2E 63 6F 6D 1B 4E  1D 74 20 09 4C 1E 1F 16  on.com.N.t .L...
```

THe flag is simply:

``` such.5h311010101@flare-on.com ```