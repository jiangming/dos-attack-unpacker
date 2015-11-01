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
    rdtsc	; read the time stamp
    mov dword ptr lot, eax  ; save low-order 32 bits

    push offset execute_1
    pop eax
    mov byte ptr [eax], 60h   ; write behavior

    
dos_attack:
    ;cpuid	; force all previous instructions to comple
    rdtsc	; read the time stamp
    mov dword ptr lot, eax  ; save low-order 32 bits
    mov dword ptr hit, edx	; save high-order 32 bits
    
    push offset execute_1
    pop eax
    mov byte ptr [eax], 60h   ; write behavior
    push offset execute_2
    pop eax 
    mov byte ptr [eax], 61h   ; write behavior
    
execute_1:
    db 0        ; execute behavior: pushad
execute_2:
    db 0        ; execute behavior: popad
    
    ;call dangerous_system_call
        
    ;cpuid           ; wait for previous instructions to complete
    rdtsc
    sub eax, dword ptr lot
    sbb edx, dword ptr hit
    mov dword ptr lot, eax
    mov dword ptr hit, edx
    ;mov lot, eax
    ;mov hit, edx
    print str$(lot)
    print chr$(" ")
    print str$(hit)
    print chr$(13,10) 
    mov eax, lot
    cmp eax, 1000
    ja dos_attack
    ;dec t  
    ;jnz dos_attack

    ;print chr$("No Unpackers!",13,10)

    exit
    
w:
    dd 0,0,0,0

    end start                       ; Tell MASM where the program ends
