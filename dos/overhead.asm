   ;ml /c /coff attack.asm
;link /subsystem:console /section:.text,ERW attack.obj

    .686                                    ; create 32 bit code
    .model flat, stdcall                    ; 32 bit memory model
    option casemap :none                    ; case sensitive

    include \masm32\include\windows.inc     ; always first
    include \masm32\macros\macros.asm       ; MASM support macros

  ; -----------------------------------------------------------------
  ; include files that have MASM format prototypes for function calls
  ; -----------------------------------------------------------------
    include \masm32\include\masm32.inc
    include \masm32\include\gdi32.inc
    include \masm32\include\user32.inc
    include \masm32\include\kernel32.inc
    include \masm32\include\Advapi32.inc

  ; ------------------------------------------------
  ; Library files that have definitions for function
  ; exports and tested reliable prebuilt code.
  ; ------------------------------------------------
    includelib \masm32\lib\masm32.lib
    includelib \masm32\lib\gdi32.lib
    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\Advapi32.lib



    .data
    hit dd  0
    lot dd  0
    t   dd  10
    
    .code   ;code section

start:
    cpuid
    rdtsc	; read the time stamp
    mov dword ptr lot, eax  ; save low-order 32 bits
    cpuid
    rdtsc
    sub eax, dword ptr lot
    mov lot, eax

    cpuid
    rdtsc	; read the time stamp
    mov dword ptr lot, eax  ; save low-order 32 bits
    cpuid
    rdtsc
    sub eax, dword ptr lot
    mov lot, eax

    
    cpuid
    rdtsc	; read the time stamp
    mov dword ptr lot, eax  ; save low-order 32 bits
    cpuid
    rdtsc
    sub eax, dword ptr lot
    mov lot, eax
    
    print str$(lot)
   
    ;dec t  
    ;jnz dos_attack

    ;print chr$("No Unpackers!",13,10)

    exit
    

    end start                       ; Tell MASM where the program ends
