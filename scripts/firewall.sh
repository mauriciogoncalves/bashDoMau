#!/bin/bash

echo ""
echo -e '\033[01;32m==========================================================================\033[00;37m'
echo -e '\033[01;32m| :::::::::::::::: SETANDO AS CONFIGURAÇÕES DO IPTABLES :::::::::::::::: |\033[00;37m'
echo -e '\033[01;32m==========================================================================\033[00;37m'

###################################################################
# Passo 1: Limpando as regras 
###################################################################
iptables -F
iptables -t filter -F INPUT
iptables -t filter -F OUTPUT
iptables -t filter -F FORWARD

iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING

iptables -t mangle -F OUTPUT
iptables -t mangle -F OUTPUT
iptables -t mangle -F FORWARD

iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING

echo "Limpando todas as regras ...........................................[ OK ]"

# Definindo a Politica Default das Cadeias
iptables -P INPUT DROP
iptables -P FORWARD DROP 
iptables -P OUTPUT ACCEPT
echo "Definindo a Politica Default das Cadeias............................[ OK ]"

###################################################################
# Passo 2: Desabilitar o trafego IP entre as placas de rede 
###################################################################

echo "0" > /proc/sys/net/ipv4/ip_forward
echo "Desabilitar o trafego IP entre as placas de rede: OFF ..............[ OK ]"

# Configurando a Protecao anti-spoofing
for spoofing in /proc/sys/net/ipv4/conf/*/rp_filter; do
echo "1" > $spoofing
done
echo "Configurando a Protecao anti-spoofing ..............................[ OK ]"

# Impedimos que um atacante possa maliciosamente alterar alguma rota
echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "Habilitando redirecionamento .......................................[ OK ]"

# Utilizado em diversos ataques, isso possibilita que o atacante determine o "caminho" que seu
# pacote vai percorrer (roteadores) ate seu destino. Junto com spoof, isso se torna muito perigoso.
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "Configurando a Proteção anti-source_route ..........................[ OK ]"

# Protecao contra responses bogus
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
echo "Configurando a Proteção anti-bugus_response ........................[ OK ]"

# Protecao contra ataques de syn flood (inicio da conexao TCP). Tenta conter ataques de DoS.
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo "Configurando a Proteção anti-synflood ..............................[ OK ]"

###################################################################
# Passo 3: Carregando os modulos do iptables 
###################################################################

modprobe ip_tables
modprobe iptable_filter
modprobe iptable_mangle
modprobe iptable_nat
modprobe ipt_MASQUERADE
echo "Carregando os módulos do iptables's ................................[ OK ]"
modprobe ip_nat_ftp ports=21,29,20

###################################################################
# Passo 4: definir o que pode passar e o que nao 
###################################################################

# Cadeia de Entrada

# LOCALHOST - ACEITA TODOS OS PACOTES
iptables -A INPUT -i lo -j ACCEPT

### PORTA 25 (SMTP)- ACEITA PARA TODOS
iptables -A INPUT -p tcp --dport 10000 -j ACCEPT
echo "Abrindo porta 22 para ssh ..........................................[ OK ]"

### PORTA 25 (SMTP)- ACEITA PARA TODOS
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
echo "Abrindo porta 22 para ssh ..........................................[ OK ]"

### PORTA 25 (SMTP)- ACEITA PARA TODOS
iptables -A INPUT -p tcp --dport 1433 -j ACCEPT
echo "Abrindo porta 22 para ssh ..........................................[ OK ]"

### PORTA 25 (SMTP)- ACEITA PARA TODOS
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
echo "Abrindo porta 22 para ssh ..........................................[ OK ]"

iptables -A INPUT -p tcp --dport 10000 -j ACCEPT
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT

# PORTA 3306 (SSH)- ACEITA PARA TODOS
#iptables -A INPUT -p tcp --dport 3306 -j ACCEPT

#permitir MySQL para rede do Sbrubbles
iptables -A OUTPUT -p tcp --dport 3306 -d  143.1.1.105 -j ACCEPT
iptables -A INPUT -p tcp --sport 3306 -s   143.1.1.105 -j ACCEPT
iptables -A FORWARD -p tcp --sport 3306 -s 143.1.1.105 -j ACCEPT
echo "Abrindo porta 3306 para mysql ......................................[ OK ]"

iptables -A INPUT -p tcp --dport 22 -j ACCEPT

#iptables -A INPUT -p tcp --dport 88 -j ACCEPT
#echo "Abrindo porta 8000 para teste ......................................[ OK ]"

 
# PORTA 3456 (SSH)- ACEITA PARA TODOS
iptables -A INPUT -p tcp --dport 3456 -j ACCEPT
echo "Abrindo porta 3456 para ssh ........................................[ OK ]"

# PORTA 80 (WEB)- ACEITA PARA TODOS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
echo "Abrindo porta 80 ...................................................[ OK ]"

# PORTA 53 (DNS)- ACEITA PARA TODOS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
echo "Abrindo porta 53 udp para dns ......................................[ OK ]"

## PORTAS 25,993,995,110,143
## respectivamente smtp, imp-ssl, pop-ssl, pop3 , imap
#iptables -A INPUT -p tcp --tcp-flags SYN,RST,ACK SYN -m limit --limit 5/s -m multiport --ports 25,993,995,110,143 -j ACCEPT
#echo "Abrindo portas 25, 993, 995, 110, 143 para servicos de e-mail.......[ OK ]"

# No iptables, temos de dizer quais sockets sao validos em uma conexao
# iptables -A INPUT -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT

iptables -A INPUT -s 143.1.1.239 -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
iptables -A INPUT -s 172.16.20.0/24 -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "Configurando as regras de INPUT ....................................[ OK ]"

####o###############################################################
# Cadeia de Reenvio (FORWARD).
###################################################################

# Primeiro, ativar o mascaramento (nat).

iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P PREROUTING ACCEPT

#rede 1
iptables -t nat -A POSTROUTING -s 172.16.20.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.16.20.0/24 -o eth2 -j DROP

#rede 2
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth1 -j DROP
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth2 -j DROP

#rede rede3
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -p tcp --dport 80 -o eth0 -j MASQUERADE

#porta https para rede3
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -p tcp --dport 443 -o eth0 -j MASQUERADE

#porta dns para rede3
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -p udp --dport 53 -o eth0 -j MASQUERADE

#porta smtp autenticado
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -p tcp --dport 587 -o eth0 -j MASQUERADE

#portas do msn
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -p tcp --dport 1863 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -p tcp --dport 110 -o eth0 -j MASQUERADE

iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o eth1 -j DROP

echo "Ativando mascaramento de IP da rede interna ........................[ OK ]"

# Agora dizemos quem e o que podem acessar externamente

# No iptables, o controle do acesso a rede externa e feito na cadeia "FORWARD"

# COMPUTADOR DO CHEFE/FUNCIONARIOS - ACEITA/REJEITA TODOS OS PACOTES
#iptables -A FORWARD -s 192.168.0.40 -j DROP

# rede interna pode tudo nos protocolos udp icmp udp
 iptables -A FORWARD -s 172.16.20.0/24 -p tcp   -i eth1 -o eth0 -j ACCEPT
 iptables -A FORWARD -s 172.16.20.0/24 -p icmp  -i eth1 -o eth0 -j ACCEPT
 iptables -A FORWARD -s 172.16.20.0/24 -p udp   -i eth1 -o eth0 -j ACCEPT

# PORTA 3128 - ACEITA PARA A REDE LOCAL
#iptables -A FORWARD -i eth1 -p tcp --dport 3128 -j ACCEPT

# Redireciona porta 80 para 3128 (squid)
#iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 3128

# No iptables, temos de dizer quais sockets sao validos em uma conexao
iptables -A FORWARD -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
echo "Setando as regras pra FORWARD ......................................[ OK ]"

# Finalmente: Habilitando o trafego IP, entre as Interfaces de rede
echo "1" > /proc/sys/net/ipv4/ip_forward
echo "Setando ip_forward: ON .............................................[ OK ]"

#prioriza trafego de saida
iptables -t mangle -A OUTPUT -o eth0 -p tcp --dport 80 -j TOS --set-tos 16

# REDIRECIONAMENTO 
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 2222 -j DNAT --to-dest 172.16.20.2
iptables -A FORWARD -p tcp -i eth0 --dport 2222 -d 172.16.20.2 -j ACCEPT
echo "Redirecionando porta TCP 2222 ssh pro microX ------> 172.16.20.2 ..[ OK ]"

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 765 -j DNAT --to-dest 172.16.20.30
iptables -A FORWARD -p tcp -i eth0 --dport 765 -d 172.16.20.30 -j ACCEPT
echo "Redirecionando porta TCP 765 emule para microY"

iptables -t nat -A PREROUTING -i eth0 -p udp --dport 567 -j DNAT --to-dest 172.16.20.30
iptables -A FORWARD -p udp -i eth0 --dport 567 -d 172.16.20.30 -j ACCEPT
echo "Redirecionando porta UDP 567 emule para patty microY"

echo "Pronto !!! Firewall: de pé! ........................................[ OK ]"
echo "Pronto !!! Ass Maurício G. Vieira ..................................[ OK ]"
echo -e '\033[01;32m==========================================================================\033[00;37m'