;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
; 《加密与解密》第三版配套实例
;  第16章 外壳编写基础
;  (c)  看雪软件安全网站 www.pediy.com 2000-2008
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
.586P
.MODEL FLAT,STDCALL
OPTION CASEMAP:NONE

include c:\masm32\include\windows.inc



PUBLIC				ShellStart0
PUBLIC				ShellEnd0
PUBLIC				ShellStart
PUBLIC				ShellEnd
PUBLIC				ImportTableBegin
PUBLIC				ImportTableEnd
PUBLIC				SHELL_DATA_0
PUBLIC				SHELL_DATA_1
PUBLIC				TlsTable
PUBLIC				RelocBaseBegin

assume 	fs:nothing


.data
    hit dd  0
    lot dd  0

.code
;**********************************************************
ShellStart0 LABEL	DWORD
	pushad                    ; 外壳入口点
	call	next0
;**********************************************************

;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;                   以下是自构造的外壳的输入表
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
ImportTableBegin  LABEL	DWORD
ImportTable	 DD	AddressFirst-ImportTable  ;OriginalFirstThunk
		 DD	0,0                       ;TimeDataStamp,ForwardChain
AppImpRVA1	 DD	DllName-ImportTable       ;Name
AppImpRVA2	 DD	AddressFirst-ImportTable  ;FirstThunk
		 DD	0,0,0,0,0
AddressFirst	 DD	FirstFunc-ImportTable     ;指向IMAGE_tHUNK_DATA
AddressSecond	 DD	SecondFunc-ImportTable    ;指向IMAGE_tHUNK_DATA
AddressThird	 DD	ThirdFunc-ImportTable     ;指向IMAGE_tHUNK_DATA
		 DD	0
DllName		 DB	'KERNEL32.dll'
		 DW	0
FirstFunc	 DW	0	
		 DB	'GetProcAddress',0
SecondFunc	 DW	0
		 DB	'GetModuleHandleA',0
ThirdFunc	 DW	0
		 DB	'LoadLibraryA',0
ImportTableEnd  LABEL	DWORD
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;               以下是自构造的假重定位表(处理DLL时用）
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
RelocBaseBegin  LABEL	DWORD
RelocBase	 DD	0
		 DD	08h
		 DD	0
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;		以下是需要由加壳程序修正的变量
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SHELL_DATA_0		LABEL	DWORD
ShellBase	 DD	0
ShellPackSize	 DD	0
TlsTable	 DB	18h dup (?)

;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;               外壳引导段使用的变量空间
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Virtualalloc	 DB	'VirtualAlloc',0
VirtualallocADDR DD	0
imagebase	 DD	0
ShellStep	 DD	0 
ShellBase2	 DD	0 

;**********************************************************
next0:
	pop	ebp
	sub	ebp,(ImportTable-ShellStart0)

	;////////////////////////////////////////////////以下代码是处理DLL时起作用
	mov	eax, dword ptr [ebp+(ShellStep-ShellStart0)]
	.if	eax != 0;dll文件退出时走这里	
		push	ebp
		jmp	dword ptr [ebp+(ShellBase2-ShellStart0)]
	.endif
	inc	dword ptr [ebp+(ShellStep-ShellStart0)]
	
	mov	eax, dword ptr [esp+24h]
	mov	dword ptr [ebp+(imagebase-ShellStart0)], eax;取当前映像基址，如果是EXE在后面会用Getmulehandle取基址的
	;////////////////////////////////////////////////

	lea	esi,[ebp+(DllName-ShellStart0)]
	push	esi
	call	dword ptr [ebp+(AddressSecond-ShellStart0)]
	lea	esi,[ebp+(Virtualalloc-ShellStart0)]
	push	esi
	push	eax
	call	dword ptr [ebp+(AddressFirst-ShellStart0)]
	mov	dword ptr [ebp+(VirtualallocADDR-ShellStart0)],eax
	push	PAGE_READWRITE
	push	MEM_COMMIT
	push	dword ptr [ebp+(ShellPackSize-ShellStart0)]
	push	0
	call	dword ptr [ebp+(VirtualallocADDR-ShellStart0)]
	push	eax
	mov	dword ptr [ebp+(ShellBase2-ShellStart0)], eax;将外壳第二段地址放到ShellBase2，dll退出时会用到
	mov	ebx,dword ptr [ebp+(ShellBase-ShellStart0)]
	add	ebx,ebp
	push	eax
	push	ebx
	call	_aP_depack_asm
	pop	edx
	push	ebp
	jmp	edx

;*******Aplib解压代码********
_aP_depack_asm:
    pushad
    mov    esi, [esp + 36]    ; C calling convention
    mov    edi, [esp + 40]
    cld
    mov    dl, 80h
    xor    ebx, ebx
literal:
    movsb
    mov    bl, 2
nexttag:
    call   getbit
    jnc    literal

    xor    ecx, ecx
    call   getbit
    jnc    codepair
    xor    eax, eax
    call   getbit
    jnc    shortmatch
    mov    bl, 2
    inc    ecx
    mov    al, 10h
getmorebits:
    call   getbit
    adc    al, al
    jnc    getmorebits
    jnz    domatch
    stosb
    jmp    short nexttag
codepair:
    call   getgamma_no_ecx
    sub    ecx, ebx
    jnz    normalcodepair
    call   getgamma
    jmp    short domatch_lastpos
shortmatch:
    lodsb
    shr    eax, 1
    jz     donedepacking
    adc    ecx, ecx
    jmp    short domatch_with_2inc
normalcodepair:
    xchg   eax, ecx
    dec    eax
    shl    eax, 8
    lodsb
    call   getgamma
    cmp    eax, 32000
    jae    domatch_with_2inc
    cmp    ah, 5
    jae    domatch_with_inc
    cmp    eax, 7fh
    ja     domatch_new_lastpos
domatch_with_2inc:
    inc    ecx
domatch_with_inc:
    inc    ecx
domatch_new_lastpos:
    xchg   eax, ebp
domatch_lastpos:
    mov    eax, ebp
    mov    bl, 1
domatch:
    push   esi
    mov    esi, edi
    sub    esi, eax
    rep    movsb
    pop    esi
    jmp    short nexttag
getbit:
    add     dl, dl
    jnz     stillbitsleft
    mov     dl, [esi]
    inc     esi
    adc     dl, dl
stillbitsleft:
    ret
getgamma:
    xor    ecx, ecx
getgamma_no_ecx:
    inc    ecx
getgammaloop:
    call   getbit
    adc    ecx, ecx
    call   getbit
    jc     getgammaloop
    ret
donedepacking:
    sub    edi, [esp + 40]
    mov    [esp + 28], edi    ; return unpacked length in eax
    popad
    ret	8h

ShellEnd0  LABEL	DWORD


;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;               外壳第二层代码
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
ShellStart LABEL	DWORD
	call	$+5
	pop	edx
	sub	edx,5h
	pop	ebp

	mov	eax, dword ptr [edx+(ShellStep_2-ShellStart)]
	.if	eax != 0;dll退出时从这里进入OEP	
	        popad
	        jmp ReturnOEP
	 .endif

	mov	ecx,3h
	lea	esi,[ebp+(AddressFirst-ShellStart0)]
	lea	edi,[edx+(GetprocaddressADDR-ShellStart)]
    MoveThreeFuncAddr:
	mov	eax,dword ptr [esi]
	mov	dword ptr [edi],eax
	add	esi,4h
	add	edi,4h
	loop	MoveThreeFuncAddr
	lea	eax,[ebp+(_aP_depack_asm-ShellStart0)]
	mov	dword ptr [edx+(aP_depackAddr-ShellStart)],eax
	mov	eax,dword ptr [ebp+(VirtualallocADDR-ShellStart0)]
	mov	dword ptr [edx+(S_VirtualallocADDR-ShellStart)],eax

	mov eax,[ebp+(imagebase-ShellStart0)]	;将DLL基址读出
	mov	ebp,edx
	mov	dword ptr [ebp+(FileHandle-ShellStart)],eax
	mov	eax, dword ptr [ebp+(S_FileIsDll-ShellStart)]
	.if	eax == 0;如果是EXE文件，则用
		push	0
		call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
		mov	dword ptr [ebp+(FileHandle-ShellStart)],eax	;取得当前文件句柄
	.endif


	;*******取一些函数入口
	lea	esi,dword ptr [ebp+(Ker32DllName-ShellStart)]
	push	esi
	call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
	.if	eax==0
		push	esi
		call	dword ptr [ebp+(LoadlibraryADDR-ShellStart)]
	.endif
	mov	esi,eax
	lea	ebx,dword ptr [ebp+(S_Virtualfree-ShellStart)]
	push	ebx
	push	esi
	call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
	mov	dword ptr [ebp+(S_VirtualfreeADDR-ShellStart)],eax


;*********************** Detect Generic Unpacking**************************************************8
start:
    rdtsc	; read the time stamp
    mov dword ptr lot, eax  ; save low-order 32 bits
    push offset execute_1
    pop eax
    mov byte ptr [eax], 60h   ; write behavior

	push offset execute_1
    pop eax
    mov byte ptr [eax], 60h   ; write behavior

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
	cmp edx, 0
	ja dos_attack
  ;  mov dword ptr lot, eax
  ;  mov dword ptr hit, edx
  ;  mov eax, lot
    cmp eax, 1500
    ja dos_attack

	;*******解压缩各段********
	mov	ebx,S_PackSection-ShellStart
    DePackNextSection:
	cmp	dword ptr [ebp+ebx],0h
	jz	AllSectionDePacked
	push	ebx
	push	PAGE_READWRITE
	push	MEM_COMMIT
	push	dword ptr [ebp+ebx]
	push	0
	call	dword ptr [ebp+(S_VirtualallocADDR-ShellStart)]	;申请内存进行读写
	pop	ebx
	mov	esi,eax
	mov	eax,ebx
	add	eax,ebp
	mov	edi,dword ptr [eax+4h]
	add	edi,dword ptr [ebp+(FileHandle-ShellStart)]
	push	esi
	push	edi
	call	dword ptr [ebp+(aP_depackAddr-ShellStart)]
	mov	ecx,dword ptr [ebp+ebx]
	push	esi
	rep	movsb
	pop	esi
	push	ebx
	push	MEM_RELEASE
	push	0
	push	esi
	call	dword ptr [ebp+(S_VirtualfreeADDR-ShellStart)]	;释放内存
	pop	ebx
	add	ebx,0ch
	jmp	DePackNextSection
    AllSectionDePacked:
	;*******恢复原输入表******
	mov	eax,dword ptr [ebp+(S_IsProtImpTable-ShellStart)]
	.if	eax == 0
		mov	edi,dword ptr [ebp+(ImpTableAddr-ShellStart)]
		add	edi,dword ptr [ebp+(FileHandle-ShellStart)]
	    GetNextDllFuncAddr:
		mov	esi,dword ptr [edi+0ch]
		.if	esi == 0
			jmp	AllDllFuncAddrGeted
		.endif
		add	esi,dword ptr [ebp+(FileHandle-ShellStart)]
		push	esi
		call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
		.if	eax==0
			push	esi
			call	dword ptr [ebp+(LoadlibraryADDR-ShellStart)]
		.endif
		mov	esi,eax
		mov	edx,dword ptr [edi]
		.if	edx == 0
			mov	edx,dword ptr [edi+10h]
		.endif
		add	edx,dword ptr [ebp+(FileHandle-ShellStart)]
		mov	ebx,dword ptr [edi+10h]
		add	ebx,dword ptr [ebp+(FileHandle-ShellStart)]
	    GetNextFuncAddr:
		mov	eax,dword ptr [edx]
		.if	eax == 0
			jmp	AllFuncAddrGeted
		.endif
		push	ebx
		push	edx
		cdq
		.if	edx == 0	
			add	eax,2h
			add	eax,dword ptr [ebp+(FileHandle-ShellStart)]
		.else
			and	eax,7fffffffh
		.endif
		push	eax
		push	esi
		call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
		mov	dword ptr [ebx],eax
		pop	edx
		pop	ebx
		add	edx,4h
		add	ebx,4h
		jmp	GetNextFuncAddr
	    AllFuncAddrGeted:
		add	edi,14h
		jmp	GetNextDllFuncAddr
	    AllDllFuncAddrGeted:
	.else
		mov	edx,dword ptr [ebp+(ImpTableAddr-ShellStart)]
		add	edx,ebp
	    GetNextDllFuncAddr2:
		mov	edi,dword ptr [edx]
		.if	edi == 0
			jmp	AllDllFuncAddrGeted2
		.endif
		add	edi,dword ptr [ebp+(FileHandle-ShellStart)]
		add	edx,5h
		mov	esi,edx
		push	esi
		call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
		.if	eax==0
			push	esi
			call	dword ptr [ebp+(LoadlibraryADDR-ShellStart)]
		.endif
		movzx	ecx,byte ptr [esi-1]
		add	esi,ecx
		mov	edx,esi
		mov	esi,eax
		inc	edx
		mov	ecx,dword ptr [edx]
		add	edx,4h
	    GetNextFuncAddr2:
		push	ecx
		movzx	eax,byte ptr [edx]
		.if	eax == 0
			inc	edx
			push	edx
			mov	eax,dword ptr [edx]
			push	eax
			push	esi
			call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
			mov	dword ptr [edi],eax
			pop	edx
			add	edx,4h
		.else
			inc	edx
			push	edx
			push	edx
			push	esi
			call	dword ptr [ebp+(GetprocaddressADDR-ShellStart)]
			mov	dword ptr [edi],eax
			pop	edx
			movzx	eax,byte ptr [edx-1]
			add	edx,eax
		.endif
		inc	edx
		add	edi,4h
		pop	ecx
		loop	GetNextFuncAddr2
		jmp	GetNextDllFuncAddr2
	    AllDllFuncAddrGeted2:
	.endif

	;*******修正重定位数据

	mov	esi, dword ptr [ebp+ (S_RelocADDR-ShellStart)]
	.if	esi != 0
		add	esi, dword ptr [ebp+(FileHandle-ShellStart)]
		mov	edi, dword ptr [ebp+(FileHandle-ShellStart)]
		mov	ebx, edi
		sub	edi, dword ptr [ebp+(S_PeImageBase-ShellStart)]
		movzx	eax, byte ptr [esi]
		.while	al
			.if al == 3h
				inc	esi
				add	ebx, dword ptr [esi]
				add	dword ptr [ebx], edi
				add	esi, 4h
			.else
				inc	esi
				add	ebx, eax
				add	dword ptr [ebx], edi
			.endif
			movzx	eax, byte ptr [esi]
		.endw
	.endif

	;*******anti  dump*****************
	push	fs:[30h]
	pop	eax
	test	eax,eax
	js	fuapfdw_is9x  
fuapfdw_isNT:
	mov	eax, [eax+0ch]
	mov	eax, [eax+0ch]
	mov	dword ptr [eax+20h], 1000h 
	jmp	fuapfdw_finished
fuapfdw_is9x:
	push	0
	call	dword ptr [ebp+(GetmulehandleADDR-ShellStart)]
	test	edx, edx
	jns	fuapfdw_finished 
	cmp	dword ptr [edx+8h], -1
	jne	fuapfdw_finished  
	mov	edx, [edx+4]  
	mov	dword ptr [edx+50h], 1000h 
fuapfdw_finished:

	inc     dword ptr [ebp+(ShellStep_2-ShellStart)] ;dll
	;*************准备返回OEP***************
	mov	eax,dword ptr [ebp+(OEP-ShellStart)]
	add	eax,dword ptr [ebp+(FileHandle-ShellStart)]
	add	dword ptr [ebp+(ReturnOEP-ShellStart)+1],eax ;eax=OEP
	popad
ReturnOEP:
	push dword ptr[0]
	ret

;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;		以下是需要由加壳程序修正的变量
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SHELL_DATA_1		LABEL	DWORD
OEP			DD	0
S_IsProtImpTable	DD	0
ImpTableAddr		DD	0
S_FileIsDll		DD	0
S_RelocADDR		DD	0  ;原始重定位地址（修正的重定数据还放在此）
S_PeImageBase           DD	0  ;原始映象基址
S_PackSection		DB	0a0h dup (?)


;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
;		以下是外壳第二段使用的变量
;^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

GetprocaddressADDR	DD	0
GetmulehandleADDR	DD	0
LoadlibraryADDR		DD	0
S_VirtualallocADDR	DD	0
FileHandle		DD	0
aP_depackAddr		DD	0
ShellStep_2             DD	0
S_VirtualfreeADDR	DD	0
Ker32DllName		DB	'KERNEL32.dll',0
S_Virtualfree		DB	'VirtualFree',0


ShellEnd LABEL		DWORD


end