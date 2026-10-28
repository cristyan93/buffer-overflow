import socket

# Substitua pelo IP da sua Máquina Virtual Windows
IP_DA_VM = "192.168.1.15"  
PORTA = 9999

try:
    print(f"[*] Tentando se conectar a {IP_DA_VM} na porta {PORTA}...")
    
    # Cria a conexão de rede (Socket)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((IP_DA_VM, PORTA))
    
    # Recebe a mensagem de boas-vindas do Vulnserver
    resposta = s.recv(1024)
    print(f"[+] Conexão estabelecida com sucesso!")
    print(f"[+] Resposta do Vulnserver: {resposta.decode('utf-8')}")
    
    s.close()
except Exception as e:
    print(f"[-] Falha na conexão. Erro: {e}")
    print("[-] Verifique se o Vulnserver está rodando, se apertou F9 no x32dbg e se a rede está em modo Bridge.")
