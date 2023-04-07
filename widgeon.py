# 
# A collection of enumeration tools that can be multi-threaded and automated
# For usage go to www.widgeonsway.ca/toolkit
#
#

import subprocess
import re
import os
import multiprocessing
def run_nmap_scan(input_file):
    with open(input_file) as f:
        content = f.read()
    match = re.search(r'Nmap scan report for (\S+)', content)
    if match is None:
        print("Error: could not extract IP address from input file")
        return
    ip_address = match.group(1)
    ports = []
    for line in content.splitlines():
        if re.search(r'^\d+/tcp\s+open', line):
            port = line.split('/')[0]
            ports.append(port)
    cmd_parts = ['nmap']
    cmd_parts.extend(['-sVC', '--script="*"'])
    cmd_parts.extend(['-p', ','.join(ports)])
    cmd_parts.extend([ip_address, '-oA', input('Output file name: ')])
    nmap_cmd = ' '.join(cmd_parts)
    try:
        subprocess.run(nmap_cmd, shell=True, check=True)
        print("Nmap scan complete")
    except subprocess.CalledProcessError as e:
        print(f"Error running Nmap: {e}")
"""
    protocols = {
        '22': 'ssh',
        '23': 'telnet',
        '25': 'smtp',
        '80': 'http',
        '110': 'pop3',
        '143': 'imap',
        '443': 'https',
        '465': 'smtps',
        '993': 'imaps',
        '995': 'pop3s',
        '1433': 'mssql',
        '3306': 'mysql',
        '3389': 'rdp',
        '5432': 'postgresql',
        '5900': 'vnc',
        '8080': 'http-proxy'
    }

"""
def extract_ports_services(file_name):
    ports = []
    services = []
    with open(file_name) as f:
        for line in f:
            fields = line.split()
            if len(fields) == 3:
                port, state, service = fields
                if '/' in port:
                    port = port.split('/')[0]
                ports.append(port)
                services.append(service)
    return ports, services



def generate_command(port, target_ip):
    commands = {
        '22': f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target_ip}:22",
        '21': [
            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target_ip}:21",
            f"ftp {target_ip}"
        ],
        '23': f"telnet {target_ip}",
        '24': f"smtp-user-enum -M VRFY -U users.txt -t {target_ip}",
        '25': f"smtp-user-enum -M VRFY -U users.txt -t {target_ip}",
        '53': [
            f"dnsrecon -r 127.0.0.0/24 -n {target_ip} -a -w -v -d results/dnsrecon/",
            f"fierce --domain {target_ip}"
        ],
        '80': [
            f"gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://{target_ip} -t 50 -x .txt,.php,.html,.bak,.old -o gobuster_dir.txt",
            f"gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://{target_ip} -t 50 -o gobuster_vhost.txt",
            f"ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://{target_ip}/FUZZ -recursion -recursion-depth 2 -o ffuf.txt"
        ],
        '161': [
            f"snmpwalk -c public -v1 {target_ip}",
            f"snmp-check -t {target_ip}",
            f"onesixtyone {target_ip}"
        ],
        '162': [
            f"snmpwalk -c public -v1 {target_ip}",
            f"snmp-check -t {target_ip}",
            f"onesixtyone {target_ip}"
        ],
        '389': [
            
            f"enum4linux -a {target_ip}"
        ],
        '445': [
            f"smbmap -H {target_ip}",
            f"nmap -p 445 --script smb-enum* {target_ip}",
            f"enum4linux {target_ip}"
        ],
        '3306': f"mysql -h {target_ip} -e 'show databases;'",
        '5432': [
            f"psql -h {target_ip} -U postgres -c '\l'",
            f"pg_dump -h {target_ip} -U postgres -Fp postgres > postgres.sql"
        ],
        '1433': [
            f"mssqlclient.py {target_ip} -windows-auth",
            f"sqlmap -u 'jdbc:sqlserver://{target_ip}:1433;databaseName=master;integratedSecurity=true' --dbms mssql --technique T --threads 10 --batch --dump-all"
        ],
        '1521': [
            f"tnscmd10g version -h {target_ip}",
            f"odat sidguesser -s {target_ip} -p 1521"
        ],
        '3389': [
            f"rdesktop {target_ip}",
            f"xfreerdp /u:username /v:{target_ip}"
        ],
        '5900': [
            f"tightvncviewer {target_ip}:0",
            f"xtightvncviewer {target_ip}:0"
        ],
        '8000': f"nmap -sV -A -T4 -p 8000 {target_ip}"
    }

    if port in commands:
        command = commands[port]
        if isinstance(command, list):
            print(f"Commands for port {port}:")
            for c in command:
                print(c)
            return command
        else:
            print(f"Command for port {port}: {command}")
            return [command]
    else:
        print(f"No valid command found for port {port}")
        return []

def ask_generate_commands(items,target_ip):
    i = 0
    while os.path.exists(f"Results_{i}.txt"):
        i += 1
    file_name = f"Results_{i}.txt"
    open(file_name, 'a').close()

    with open(file_name, 'a') as f:
        for item in items:
            command_list = generate_command(item,target_ip)
            for command in command_list:
                f.write(command + '\n')


def generate_commandz(port, target_ip):
    commands = {
        'ssh': f"hydra -l admin -P /usr/share/wordlists/rockyou.txt  ssh://{target_ip}:22",
        'ftp': [
            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target_ip}:21",
            f"ftp {target_ip}"
        ],
        'telnet': f"telnet {target_ip}",
        'smtp': f"smtp-user-enum -M VRFY -U users.txt -t {target_ip}",
        'dns': [
            f"dnsrecon -r 127.0.0.0/24 -n {target_ip} -a -w -v -d results/dnsrecon/",
            f"fierce --domain {target_ip}"
        ],
        'http': [
            f"gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://{target_ip} -t 50 -x .txt,.php,.html,.bak,.old -o gobuster_dir.txt",
            f"gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://{target_ip} -t 50 -o gobuster_vhost.txt",
            f"ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://{target_ip}/FUZZ -recursion -recursion-depth 2 -o ffuf.txt"
        ],
        'snmp': [
            f"snmpwalk -c public -v1 {target_ip}",
            f"snmp-check -t {target_ip}",
            f"onesixtyone {target_ip}"
        ],
        'ldap': [
           
            f"enum4linux -a {target_ip}"
        ],
        'smb': [
            f"smbmap -H {target_ip}",
            f"nmap -p 445 --script smb-enum* {target_ip}",
            f"enum4linux {target_ip}"
        ],
        'mysql': f"mysql -h {target_ip} -e 'show databases;'",
        'postgresql': [
            f"psql -h {target_ip} -U postgres -c '\l'",
            f"pg_dump -h {target_ip} -U postgres -Fp postgres > postgres.sql"
        ],
        'mssql': [
            f"mssqlclient.py {target_ip} -windows-auth",
            f"sqlmap -u 'jdbc:sqlserver://{target_ip}:1433;databaseName=master;integratedSecurity=true' --dbms mssql --technique T --threads 10 --batch --dump-all"
        ],
        'oracle': [
            f"tnscmd10g version -h {target_ip}",
            f"odat sidguesser -s {target_ip} -p 1521"
        ],
        'rdp': [
            f"rdesktop {target_ip}",
            f"xfreerdp /u:username /v:{target_ip}"
        ],
        'vnc': [
            f"tightvncviewer {target_ip}:0",
            f"xtightvncviewer {target_ip}:0"
        ],
        'other': f"nmap -sV -A -T4 -p 8000 {target_ip}"
    }

    if port in commands:
        command = commands[port]
        if isinstance(command, list):
            print(f"Commands for port {port}:")
            for c in command:
                print(c)
            return command
        else:
            print(f"Command for port {port}: {command}")
            return [command]
    else:
        print(f"No valid command found for port {port}")
        return []

def ask_generate_commandz(items,target_ip):
    i = 0
    while os.path.exists(f"Results_{i}.txt"):
        i += 1
    file_name = f"ServiceResults_{i}.txt"
    open(file_name, 'a').close()

    with open(file_name, 'a') as f:
        for item in items:
            command_list = generate_commandz(item,target_ip)
            for command in command_list:
                f.write(command + '\n')


def process_commands_from_file(file_path):
    with open(file_path, "r") as f:
        commands = f.readlines()

    with multiprocessing.Pool(processes=os.cpu_count()) as pool:
        pool.map(run_command, commands)

def run_command(command):
    command = command.strip()
    output_dir = "results/" + command.split()[0]
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "output.txt")
    os.system(f"{command} > {output_file}")







