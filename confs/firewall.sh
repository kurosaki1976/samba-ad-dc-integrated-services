#!/bin/bash

##################### iptables IPv4 standalone firewall script ############################
#                                                                                         #
# Este script provee un firewall para servidores que no funcionan como gateways. Mitiga   #
# los barridos de puertos (port scanners), los ataques de fuerza bruta al protocolo SSH y #
# permite sólo los ICMP tipo 8 (echo request). Se recomienda su uso conjuntamente con los #
# mecanismos de monitoreo, detección y protección "fail2ban" y "sshguard".                #
#                                                                                         #
# El listado de hosts que hicieron barridos de puertos se pude visualizar, ejecutando:    #
# cat /proc/net/xt_recent/[TCP-PORTSCAN|UDP-PORTSCAN]                                     #
#                                                                                         #
# El listado de hosts bloqueados por intentos de acceso SSH por fuerza bruta:             #
# cat /proc/net/xt_recent/sshbf                                                           #
#                                                                                         #
# Para eliminar los hosts detectados/bloqueados, ejecutar como root:                      #
# echo / > /proc/net/xt_recent/[TCP-PORTSCAN|UDP-PORTSCAN|sshbf]                          #
#                                                                                         #
# Debian/Ubuntu: apt install iptables-persistent netfilter-persistent                     #
# RHEL/CentOS: yum/dnf install iptables-service                                           #
#                                                                                         #
# por Ixen Rodríguez Pérez (ixenrp1976@gmail.com)                                         #
#     Kurosaki1976 (https://github.com/kurosaki1976)                                      #
#     GNU/Linux Proud User #313158                                                        #
#                                                                                         #
###########################################################################################

IPTABLES="/usr/sbin/iptables"

## Limpiar todos los contadores, cadenas, reglas y políticas existentes
#
$IPTABLES -Z
$IPTABLES -t nat -F
$IPTABLES -t mangle -F
$IPTABLES -F
$IPTABLES -X

## Crear cadenas perzonalizadas para abrir puertos específicos en el firewall
## y monitorear/registrar acceso SSH
#
$IPTABLES -N TCP
$IPTABLES -N UDP
$IPTABLES -N IN_SSH
$IPTABLES -N LOG_AND_DROP

## Establecer políticas por defecto
#
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -P INPUT DROP

## Crear reglas generales
#
$IPTABLES -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j IN_SSH
$IPTABLES -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j TCP

## Protección contra barridos de puertos (tricking port scanners)
#
$IPTABLES -A INPUT -p tcp -m recent --set --name TCP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with tcp-reset
$IPTABLES -A INPUT -p udp -m recent --set --name UDP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with icmp-port-unreachable

## Denegar resto conexiones entrantes
#
$IPTABLES -A INPUT -j REJECT --reject-with icmp-proto-unreachable

## INICIO REGLAS DE ACCESO PERZONALIZADAS CADENAS TCP/UDP (descomentar según necesidad)
#
# Permitir acceso protocolo SSH (TCP/22)
$IPTABLES -A TCP -p tcp -m tcp --dport 22 -j ACCEPT

# Permitir acceso consultas DNS (UDP/53,"TCP/53 transferencia de zonas")
#$IPTABLES -A UDP -p udp -m udp --dport 53 -j ACCEPT
#$IPTABLES -A TCP -p tcp -m tcp --dport 53 -j ACCEPT

# Permitir acceso consultas DNS over TLS (UDP/853,"TCP/853 transferencia de zonas")
#$IPTABLES -A UDP -p udp -m udp --dport 853 -j ACCEPT
#$IPTABLES -A TCP -p tcp -m tcp --dport 853 -j ACCEPT

# Permitir acceso protocolo NTP (UDP/123)
#$IPTABLES -A UDP -p udp -m udp --dport 123 -j ACCEPT

# Permitir acceso protocolo DHCP (UDP/67,68)
#$IPTABLES -A UDP -p udp -m udp -m multiport --dports 67,68 -j ACCEPT

# Permitir acceso protocolo WWW (TCP/80,443)
#$IPTABLES -A TCP -p tcp -m tcp -m multiport --dports 80,443 -j ACCEPT

# Permitir acceso protocolo SMTP MTA (TCP/25)
#$IPTABLES -A TCP -p tcp -m tcp --dport 25 -j ACCEPT

# Permitir acceso protocolos email MUA (recomendados protocolos seguros SSL/TLS y STARTTLS):
# SMTPs/IMAP/IMAPs/POP3/POP3s/SUBMISSION (TCP/465,143,993,110,995,587)
#$IPTABLES -A TCP -p tcp -m tcp -m multiport --dports 465,143,993,110,995,587 -j ACCEPT

# Permitir acceso protocolo XMPP:
# (TCP/5222 "xmpp-client",TCP/5269 "xmpp-server")
# (TCP/5280 "ejabberd webui",TCP/9090,9091 "openfire webui")
#$IPTABLES -A TCP -p tcp -m tcp -m multiport --dports 5222,5269 -j ACCEPT
#$IPTABLES -A TCP -p tcp -m tcp --dport 5280 -j ACCEPT
#$IPTABLES -A TCP -p tcp -m tcp -m multiport --dports 9090,9091 -j ACCEPT

# Permitir acceso protocolo FTP (TCP/20,21)
# Modo pasivo, definir rango de puertos entre 1025 y 65535
#$IPTABLES -A TCP -p tcp -m tcp -m multiport --dports 20,21,1025:65535 -j ACCEPT

# Permitir acceso servicio proxy (TCP/3128,8080)
#$IPTABLES -A TCP -p tcp -m tcp --dport 3128 -j ACCEPT
#$IPTABLES -A TCP -p tcp -m tcp --dport 8080 -j ACCEPT

# Permitir acceso servicio Samba-ADDC+DHCP (active directory domain controller)
#$IPTABLES -A UDP -p udp -m udp -m multiport --dports 53,67,68,88,123,137,138,389,464 -j ACCEPT
#$IPTABLES -A TCP -p tcp -m tcp -m multiport --dports 53,88,135,139,389,445,464,636,3268,3269,49152:65535 -j ACCEPT

# Protección contra barridos UDP/ACK/SYN (-sU/-sA/-sS scans in nmap)
#
$IPTABLES -A TCP -p tcp -m recent --update --seconds 60 --name TCP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with tcp-reset
$IPTABLES -A UDP -p udp -m recent --update --seconds 60 --name UDP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with icmp-port-unreachable
#
## FIN REGLAS DE ACCESO PERZONALIZADAS CADENAS TCP/UDP

## Crear reglas de protección contra ataques fuerza bruta SSH (bruteforce attacks)
#
$IPTABLES -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 3 --seconds 10 -j LOG_AND_DROP
$IPTABLES -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 4 --seconds 1800 -j LOG_AND_DROP
$IPTABLES -A IN_SSH -m recent --name sshbf --set -j ACCEPT
$IPTABLES -A LOG_AND_DROP -j LOG --log-prefix "iptables deny: " --log-level 7
$IPTABLES -A LOG_AND_DROP -j DROP

## Protección contra ataques de suplantación (spoofing attacks)
#
$IPTABLES -t raw -I PREROUTING -m rpfilter --invert -j DROP

exit 0
