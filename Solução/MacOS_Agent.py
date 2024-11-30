import os
import subprocess
import re
import hashlib

import time
from datetime import datetime

import psutil

import json
import random
#####################################################################
LOG_FILE = "/var/log/security_monitor.log"
MATRICULA_FUNCIONARIO = [
    '319519', '116138', '462213', '898691', '264963',
    '514800', '922253', '915190', '666780', '210040',
    '660133', '435942', '982716', '811394', '937889'
]

# Intervalos de verificação em segundos (ajustáveis)
INTERVALO_VERIFICACAO_DOWNLOADS = 30
INTERVALO_VERIFICACAO_USUARIOS = 30
INTERVALO_VERIFICACAO_SENHAS = 60
INTERVALO_VERIFICACAO_LOGINS_INVALIDOS = 60
INTERVALO_VERIFICACAO_ESCALONAMENTO_PRIVILEGIOS = 60
INTERVALO_VERIFICACAO_INTEGRIDADE_SISTEMA = 60
INTERVALO_VERIFICACAO_CONEXOES_REDE = 60
INTERVALO_VERIFICACAO_PROCESSOS = 60
INTERVALO_VERIFICACAO_FIREWALL = 60

def log(codigo_ataque, mensagem_log):
    log_data = {
        "matricula_funcionario": random.choice(MATRICULA_FUNCIONARIO),
        "codigo_ataque": codigo_ataque,
        "mensagem_log": mensagem_log
    }
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(log_data) + "\n")

#####################################################################
# Obtém o nome do usuário original que invocou o sudo, se aplicável
def get_download_dir():
    if os.getenv("SUDO_USER"):  # Verifica se o script foi executado com sudo
        # Pega o diretório home do usuário que invocou o sudo
        home_dir = os.path.expanduser(f"~{os.getenv('SUDO_USER')}")
    else:
        # Pega o diretório home do usuário atual
        home_dir = os.path.expanduser("~")
    return os.path.join(home_dir, "Downloads")
download_dir = get_download_dir()

# Função para calcular o MD5 de um arquivo
def calculate_md5(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()

# Função para obter os nomes dos arquivos no diretório
def get_file_names(directory):
    return set(os.listdir(directory))

# Função para monitorar o diretório de downloads
def monitorar_downloads():
    # Lista para armazenar os nomes dos arquivos já vistos
    seen_files = get_file_names(download_dir)

    while True:
        # Espera 60 segundos
        time.sleep(INTERVALO_VERIFICACAO_DOWNLOADS)

        # Obtém a lista atual de arquivos
        current_files = get_file_names(download_dir)

        # Determina os arquivos novos
        new_files = current_files - seen_files

        # Se houver novos arquivos, calcula o MD5
        for new_file in new_files:
            file_path = os.path.join(download_dir, new_file)
            if os.path.isfile(file_path):
                md5_hash = calculate_md5(file_path)
                log("T1078", f"Arquivo baixado: {new_file}, MD5: {md5_hash}")

        # Atualiza a lista de arquivos vistos
        seen_files = current_files
#####################################################################
def usuarios_atual_func():
    result = subprocess.run(['dscl', '.', '-list', '/Users'], capture_output=True, text=True)
    resultspasswd = set()
    usuarios_atual = set(result.stdout.splitlines())

    for usuario in usuarios_atual:
        resulta = subprocess.run(['dscl', '.', 'read', f'/Users/{usuario}', 'accountPolicyData'], capture_output=True, text=True)
  
        # Executa o comando de processamento e obtém o resultado
        if len(resulta.stdout) > 150:
            match = re.search(r'<key>passwordLastSetTime</key>\s*<real>([^<]+)</real>', resulta.stdout)
            if (match != None):
                resultspasswd.add(f'{usuario}: {match.group(1)}')
    
    return usuarios_atual,resultspasswd

def monitorar_novos_usuarios_senhas():
    usuarios_anteriores, passwd_anteriores = usuarios_atual_func()
    while True:
        usuarios_atual,passwd_atual = usuarios_atual_func()
        

        novos_usuarios = usuarios_atual - usuarios_anteriores
        novos_pass = passwd_anteriores - passwd_atual

        for usuario in novos_pass:
            log("T1059", f"Nova senha detectada para o usuário: {usuario.split(':')[0]}")

        
        for usuario in novos_usuarios:
            log("T1134", f"Novo usuário criado: {usuario}")
        

        usuarios_anteriores = usuarios_atual
        passwd_anteriores = passwd_atual
        
        time.sleep(INTERVALO_VERIFICACAO_USUARIOS)
#####################################################################
def monitorar_logins_invalidos():
    while True:

        command = [
            'log', 'show',
            '--predicate', '(eventMessage CONTAINS "Authentication failed")',
            '--style', 'syslog',
            '--last', f"{INTERVALO_VERIFICACAO_LOGINS_INVALIDOS-1}s"
        ]
        result = subprocess.run(command, capture_output=True, text=True)

        x = 0
        for linha in result.stdout.splitlines():
            if x == 0:
                if "Authentication failed" in linha:
                    match = re.search(r'\(([A-F0-9-]{36})\)', linha)
                    log("T1078", f"Tentativa de login inválida na conta(UUID): {match.group(1)}")
            x+=1

            if x == 3:
                x = 0
        time.sleep(INTERVALO_VERIFICACAO_LOGINS_INVALIDOS)

def monitorar_escalonamento_privilegios():
    while True:
        # Comando para buscar logs relacionados a "UserShell"
        command = [
            'log', 'show',
            '--predicate', 'eventMessage CONTAINS "UserShell"',
            '--info', '--style', 'syslog',
            '--last', f"{INTERVALO_VERIFICACAO_LOGINS_INVALIDOS-2}s"
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        result = result.stdout.splitlines()

        if(len(result) >= 5):
            log("T1134", f"Possível Escalonamento de privilégios")

        
        time.sleep(INTERVALO_VERIFICACAO_LOGINS_INVALIDOS)

def get_processos():
    processos_atual = set(f"Name: {p.name()} User:{p.username()}" for p in psutil.process_iter(['name', 'username']))
    return processos_atual

def monitorar_processos():
    processos_anteriores = get_processos()
    while True:
        processos_atual = get_processos()
        novos_processos = processos_atual - processos_anteriores
        for processo in novos_processos:
            log("T1059", f"Novo processo detectado: {processo}")
        processos_anteriores = processos_atual
        time.sleep(INTERVALO_VERIFICACAO_PROCESSOS)

def monitorar_firewall():
    regras_firewall_anteriores = subprocess.run(['pfctl', '-sr'], capture_output=True, text=True)
    regras_firewall_anteriores = regras_firewall_anteriores.stdout.splitlines()
    
    while True:
        result = subprocess.run(['pfctl', '-sr'], capture_output=True, text=True)
        regras_firewall_atual = result.stdout.splitlines()

        novas_regras = set(regras_firewall_atual) - set(regras_firewall_anteriores)
        for regra in novas_regras:
            log("T1049", f"Alteração nas regras do firewall detectada: {regra}")

            regras_firewall_anteriores = regras_firewall_atual
        time.sleep(INTERVALO_VERIFICACAO_FIREWALL)

def monitorar_conexoes_rede():
    # Obtém a lista inicial de conexões
    conexoes_anteriores = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
    conexoes_anteriores = set(line for line in conexoes_anteriores.stdout.splitlines() if "ESTABLISHED" in line)

    while True:
        # Obtém a lista atual de conexões
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        conexoes_atual = set(line for line in result.stdout.splitlines() if "ESTABLISHED" in line)

        # Identifica novas conexões
        novas_conexoes = conexoes_atual - conexoes_anteriores
        for conexao in novas_conexoes:
            log("T1049", f"Nova conexão de rede estabelecida: {conexao}")

        # Atualiza a lista de conexões anteriores
        conexoes_anteriores = conexoes_atual

        # Aguarda antes de realizar a próxima verificação
        time.sleep(INTERVALO_VERIFICACAO_CONEXOES_REDE)

def monitorar_integridade_sistema():

    arquivos_criticos = [
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        "/Library/Preferences/SystemConfiguration/com.apple.Boot.plist",
    ]

    def calcular_hashes(arquivo):
        with open(arquivo, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
        

    estado_inicial_hashes = set()

    for arquivo in arquivos_criticos:
        if os.path.isfile(arquivo):
            estado_inicial_hashes.add((arquivo, calcular_hashes(arquivo)))

        else:
            estado_inicial_hashes.add((arquivo, "Não encontrado"))   
    
    log("T1049", "Estado inicial de integridade do sistema criado.")
    
    while True:
        estado_atual_hashes = set()
        for arquivo in arquivos_criticos:
            if os.path.isfile(arquivo):
                estado_atual_hashes.add((arquivo, calcular_hashes(arquivo)))
            else:
                estado_atual_hashes.add((arquivo, "Não encontrado"))
        
        if estado_inicial_hashes != estado_atual_hashes:
            # Comparar o estado inicial com o estado atual
            for arquivo_inicial, hash_inicial in estado_inicial_hashes:
                for arquivo_atual, hash_atual in estado_atual_hashes:
                    if arquivo_inicial == arquivo_atual and hash_inicial != hash_atual:
                        log("T1049", f"Alteração detectada na integridade do sistema: Alteração no arquivo: {arquivo_inicial} - {hash_inicial} -> {hash_atual}")

        estado_inicial_hashes = estado_atual_hashes                

        time.sleep(INTERVALO_VERIFICACAO_INTEGRIDADE_SISTEMA)
# Executa a função de monitoramento
if __name__ == "__main__":
    import threading
    threads = [
        threading.Thread(target=monitorar_downloads),
        threading.Thread(target=monitorar_novos_usuarios_senhas),
        threading.Thread(target=monitorar_logins_invalidos),
        threading.Thread(target=monitorar_escalonamento_privilegios),
        threading.Thread(target=monitorar_integridade_sistema),
        threading.Thread(target=monitorar_conexoes_rede),
        threading.Thread(target=monitorar_processos),
        threading.Thread(target=monitorar_firewall)
    ]
    for t in threads:
            t.start()
    
    for t in threads:
        t.join()
