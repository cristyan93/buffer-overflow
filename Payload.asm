
xor eax, eax            ;limpa o resgistrador eax
mov eax, [fs:0x30]      ;eax apontando para o inicio da PEB
mov eax, [eax, 0x0c]    ;eax aponta agora para PEB_LDR_DATA
mov ebx, [eax + 0x14]	; EBX aponta para a lista de módulos (primeiro módulo)
mov ebx, [ebx]          ; Pula do executável principal para a ntdll.dll
mov ebx, [ebx]          ; Pula da ntdll.dll para a kernel32.dll
mov edx, [ebx + 0x10]   ; EDX agora guarda o Endereço Base dinâmico da kernel32.dll!


; --- LOCALIZAR A TABELA DE EXPORTAÇÃO (EAT) ---
mov     eax, [edx + 0x3c]    ; RVA do cabeçalho PE (Offset DOS to NT header)
mov     ecx, [edx + eax + 0x78] ; RVA da Export Table Data Directory
add     ecx, edx             ; Endereço real da Export Table (Data Directory)
mov     eax, [ecx + 0x20]    ; RVA da Address of Names (Tabela de Nomes)
add     eax, edx             ; Endereço real da Address of Names
mov     [esp + 0x4], eax     ; Salva o endereço da Tabela de Nomes na pilha temporariamente

; ---  CONFIGURAR OS CONTADORES DO LOOP ---
xor     ebx, ebx             ; EBX será o nosso contador de índice (0, 1, 2...)

.proxima_funcao:
mov     eax, [esp + 0x4]     ; Recupera o endereço da Tabela de Nomes
mov     eax, [eax + ebx*4]   ; Pega o RVA do nome da função atual no índice EBX
add     eax, edx             ; Endereço real do texto do nome da função

; --- CHECAR SE A FUNÇÃO É A "GetProcAddress" ---
;testamos as primeiras letras 
; "GetP" (em hex invertido: 0x50746547) para economizar espaço e evitar loops complexos.
  
cmp     dword [eax], 0x50746547 ; Compara os primeiros 4 bytes com "GetP"
jnz     .incrementar_index   ; Se não for igual, pula para a próxima
cmp     dword [eax + 0x4], 0x41636f72 ; Compara os próximos 4 bytes com "rocA"
jnz     .incrementar_index   ; Se não for igual, pula para a próxima

; Se passou pelos dois filtros, encontramos a GetProcAddress!
; ---  EXTRAIR O ENDEREÇO REAL DA FUNÇÃO ---
mov     eax, [ecx + 0x24]    ; RVA da Address of Name Ordinals
add     eax, edx             ; Endereço real da Tabela de Ordinais
movzx   ebx, word [eax + ebx*2] ; Pega o número ordinal da nossa função

mov     eax, [ecx + 0x1c]    ; RVA da Address of Functions (Tabela de Endereços)
add     eax, edx             ; Endereço real da Tabela de Endereços
mov     eax, [eax + ebx*4]   ; Pega o RVA exato da função GetProcAddress
add     eax, edx             ; Soma com o endereço base da DLL. 
                             ; EAX agora guarda o endereço de memória real da GetProcAddress!

mov     esi, eax             ; Move para ESI (conforme planejamos nos passos anteriores)
jmp     .busca_concluida     ; Sai do loop

.incrementar_index:
inc     ebx                  ; Soma 1 ao contador (vai para a próxima função da lista)
jmp     .proxima_funcao

.busca_concluida:
; Daqui para frente, ESI guarda a GetProcAddress. 
; Você pode executar os passos 3, 4 e o script Python que estruturamos antes.
