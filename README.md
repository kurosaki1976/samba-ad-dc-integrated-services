# Guía para la implementación de servicios integrados a Samba4 como Active Directory Domain Controller (AD DC) en Debian 9/10

## Autores

- [Ixen Rodríguez Pérez - kurosaki1976](ixenrp1976@gmail.com)
- [Yoel Torres Vázquez - oneohthree](yoel.torres.v@gmail.com)

## Tabla de contenidos

- [Consideraciones previas](#consideraciones-previas)
- [Configuración de los parámetros de red](#configuración-de-los-parámetros-de-red)
  - [Samba AD DC Server](#samba-ad-dc-server)
  - [Squid Proxy Server](#squid-proxy-server)
  - [eJabberd XMPP Server](#ejabberd-xmpp-server)
  - [Postfix/Dovecot/Roundcube Mail Server](#postfixdovecotroundcube-mail-server)
- [Sincronización de tiempo](#sincronización-de-tiempo)
  - [Samba AD DC Server](#samba-ad-dc-server-1)
  - [Squid Proxy Server](#squid-proxy-server-1)
  - [eJabberd XMPP Server](#ejabberd-xmpp-server-1)
  - [Postfix/Dovecot/Roundcube Mail Server](#postfixdovecotroundcube-mail-server-1)
- [Instalación y configuración de Samba4 como AD DC](#instalación-y-configuración-de-samba4-como-ad-dc)
  - [Instalación de paquetes necesarios](#instalación-de-paquetes-necesarios)
  - [Preparación del aprovisionamiento](#preparación-del-aprovisionamiento)
  - [Aprovisionamiento Samba Active Directory Domain Controller](#aprovisionamiento-samba-active-directory-domain-controller)
  - [Configuración de Kerberos](#configuración-de-kerberos)
  - [Comprobaciones](#comprobaciones)
- [Configuración del servidor Bind9 DNS](#configuración-del-servidor-bind9-dns)
  - [Integración con Samba AD DC](#integración-con-samba-ad-dc)
  - [Modificación del aprovisionamiento AD DC](#modificación-del-aprovisionamiento-ad-dc)
  - [Creación de zona inversa y registro PTR del servidor](#creación-de-zona-inversa-y-registro-ptr-del-servidor)
  - [Comprobaciones](#comprobaciones-1)
- [Configuración del servidor NTP](#configuración-del-servidor-ntp)
  - [Integración con Samba AD DC](#integración-con-samba-ad-dc-1)
  - [Comprobaciones](#comprobaciones-2)
- [Configuración del servidor DHCP](#configuración-del-servidor-dhcp)
  - [Integración con Samba AD DC](#integración-con-samba-ad-dc-1)
  - [Integración con Bind9 DNS](#integración-con-bind9-dns-2)
  - [Comprobaciones](#comprobaciones-3)
- [Creación de Unidades Organizativas, Grupos y Cuentas de Usuarios](#creación-de-unidades-organizativas-grupos-y-cuentas-de-usuarios)
  - [Creación de Unidades Organizativas (Organizational Units - OU)](#creación-de-unidades-organizativas-organizational-units---ou)
  - [Creación de Grupos](#creación-de-grupos)
  - [Creación de Cuentas de Usuarios](#creación-de-cuentas-de-usuarios)
- [Creación de Políticas de Grupos (Group Policy Object - GPO)](#creación-de-políticas-de-grupos-group-policy-object---gpo)
  - [Comprobaciones](#comprobaciones-3)
- [Instalación y configuración de Squid Proxy e integración con Samba AD DC](#instalación-y-configuración-de-squid-proxy-e-integración-con-samba-ad-dc)
  - [Instalación de paquetes necesarios](#instalación-de-paquetes-necesarios-1)
  - [Integración con Samba AD DC](#integración-con-samba-ad-dc-2)
  - [Comprobaciones](#comprobaciones-4)
- [Instalación y configuración de eJabberd XMPP Server e integración con Samba AD DC](#instalación-y-configuración-de-ejabberd-xmpp-server-e-integración-con-samba-ad-dc)
  - [Instalación de paquetes necesarios](#instalación-de-paquetes-necesarios-2)
  - [Creación de registros DNS](#creación-de-registros-dns)
  - [Comprobaciones](#comprobaciones-5)
  - [Integración con Samba AD DC](#integración-con-samba-ad-dc-3)
  - [Configuración del servicio](#configuración-del-servicio)
  - [Compartir el roster de los usuarios](#compartir-el-roster-de-los-usuarios)
  - [Personalizar vCard de los usuarios](#personalizar-vcard-de-los-usuarios)
  - [Comprobaciones](#comprobaciones-6)
- [Instalación y configuración de Postfix/Dovecot Mail Server e integración con Samba AD DC.](#instalación-y-configuración-de-postfixdovecot-mail-server-e-integración-con-samba-ad-dc)
  - [Instalación de paquetes necesarios](#instalación-de-paquetes-necesarios-3)
  - [Configuración del sistema](#configuración-del-sistema)
  - [Integración con Samba AD DC](#integración-con-samba-ad-dc-4)
  - [Configuración de Postfix](#configuración-de-postfix)
    - [Comprobaciones](#comprobaciones-7)
  - [Configuración del servicio Dovecot](#configuración-del-servicio-dovecot)
    - [Integración con Samba AD DC](#integración-con-samba-ad-dc-5)
  - [Configuración del servicio Webmail](#configuración-del-servicio-webmail)
    - [Roundcubemail](#roundcubemail)
    - [PostgreSQL](#postgresql)
    - [Nginx](#nginx)
    - [Apache2](#apache2)
    - [Autodescubrimiento y autoconfiguración](#autodescubrimiento-y-autoconfiguración)
- [Comandos y herramientas útiles](#comandos-y-herramientas-útiles)
- [Consideraciones finales](#consideraciones-finales)
- [Referencias](#referencias)
  - [Samba AD DC+Bind9 DNS Server+NTP+DHCP](#samba-ad-dcbind9-dns-serverntpdhcp)
  - [Squid Proxy Server](#squid-proxy-server-2)
  - [eJabberd XMPP Server](#ejabberd-xmpp-server-2)
  - [Postfix/Dovecot/Roundcube Mail Server](#postfixdovecotroundcube-mail-server-2)
  - [Proxmox VE](#proxmox-ve)
- [Anexos](#anexos)
  - [Ficheros de configuración prinicipal Squid+Samba AD DC]
    - [Debian 9 Stretch Squid 3.5](confs/proxy/squid/squid-3.5.conf)
    - [Debian 10 Buster Squid 4.6](confs/proxy/squid/squid-4.6.conf)
  - [Ficheros de configuración prinicipal eJabberd+Samba AD DC]
    - [Debian 9 Stretch eJabberd 16.09](confs/xmpp/ejabberd/ejabberd-16.09.yml)
    - [Debian 10 Buster eJabberd 18.12](confs/xmpp/ejabberd/ejabberd-18.12.yml)
  - [Ficheros de configuración prinicipal Postfix+Samba AD DC]
    - [Configuración general](confs/mail/postfix/main.cf)
    - [Configuración de servicios](confs/mail/postfix/master.cf)
  - [Ficheros de configuración prinicipal Dovecot+Samba AD DC]
    - [Debian 9 Stretch Dovecot 2.2](confs/mail/dovecot/dovecot-2.2.conf)
    - [Debian 10 Buster Dovecot 2.3](confs/mail/dovecot/dovecot-2.3.conf)
  - [Fichero de configuración prinicipal Roundcube+Samba AD DC](confs/mail/www/roundcube/config.inc.php)
  - [Ficheros de publicación web Roundcube]
    - [Servidor Web Nginx](confs/mail/www/nginx/roundcube)
    - [Servidor Web Apache](confs/mail/www/apache2/roundcube.conf)
    - [Microsoft Outlook Autodiscover](confs/mail/www/autodiscover.xml)
    - [Mozilla Thunderbird Autoconfig](confs/mail/www/config-v1.1.xml)

## Consideraciones previas

Esta guía no presenta configuraciones avanzadas, tales como filtrado de contenido web, técnicas de antispam y antivirus o filtrado de origen y
destino de email; sino que está enfocada en exponer la integración de servicios vitales -proxy, chat y correo electrónico-, en una red corporativa con el servicio de directorio `Samba AD DC`; aunque pudieran incluirse en futuras revisiones.

Tendiendo en cuenta esto, se pautan las siguientes premisas:

* Sistema Operativo: Debian GNU/Linux 9/10 (instalación base)
* Repositorio de paquetes distribución Debian 9/10
* Repositorio de paquetes Samba 4.9.6
* Existencia de un servidor NTP superior
* Existencia de un servidor proxy padre
* Nombre de host Samba AD DC: `dc`
* Dirección IP Samba AD DC: `192.168.0.1`
* Nombre de host Squid Proxy Server: `proxy`
* Dirección IP Squid Proxy Server: `192.168.0.2`
* Nombre de host eJabberd XMPP Server: `jb`
* Dirección IP eJabberd XMPP Server: `192.168.0.3`
* Nombre de host Postfix/Dovecot/Roundcube Mail Server: `mail`
* Dirección IP Postfix/Dovecot/Roundcube Mail Server: `192.168.0.4`
* Nombre de dominio: `example.tld`
* Los hosts miembros del dominio deben usar Samba AD DC como servidor DNS y de tiempo.

> **NOTA**: La última premisa se logrará mediante la implementación de un servidor `DHCP` que permita las asiganción de parámetros de red dinámicos.

## Configuración de los parámetros de red

### Samba AD DC Server

```bash
nano /etc/network/interfaces

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 192.168.0.1/24
    gateway 192.168.0.254
    dns-nameservers 127.0.0.1
    dns-search example.tld
```

```bash
nano /etc/hosts

127.0.0.1       localhost
192.168.0.1     dc.example.tld      dc
```

```bash
nano /etc/resolv.conf

domain example.tld
nameserver 127.0.0.1
```

### Squid Proxy Server

```bash
nano /etc/network/interfaces

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 192.168.0.2/24
    gateway 192.168.0.254
    dns-nameservers 192.168.0.1
    dns-search example.tld
```

```bash
nano /etc/hosts

127.0.0.1       localhost
192.168.0.2     proxy.example.tld      proxy
```

```bash
nano /etc/resolv.conf

domain example.tld
nameserver 192.168.0.1
```

### eJabberd XMPP Server

```bash
nano /etc/network/interfaces

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 192.168.0.3/24
    gateway 192.168.0.254
    dns-nameservers 192.168.0.1
    dns-search example.tld
```

```bash
nano /etc/hosts

127.0.0.1       localhost
192.168.0.3     jb.example.tld      jb
```

```bash
nano /etc/resolv.conf

domain example.tld
nameserver 192.168.0.1
```

### Postfix/Dovecot/Roundcube Mail Server

```bash
nano /etc/network/interfaces

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 192.168.0.4/24
    gateway 192.168.0.254
    dns-nameservers 192.168.0.1
    dns-search example.tld
```

```bash
nano /etc/hosts

127.0.0.1       localhost
192.168.0.4     mail.example.tld      mail
```

```bash
nano /etc/resolv.conf

domain example.tld
nameserver 192.168.0.1
```

## Sincronización de tiempo

Utilizar el cliente NTP de systemd.

```bash
timedatectl set-ntp true
```

Definir el servidor de tiempo superior.

```bash
mv /etc/systemd/timesyncd.conf{,.org}
nano /etc/systemd/timesyncd.conf
```

### Samba AD DC Server

```bash
[Time]
NTP=ntp.tld
```

### Squid Proxy Server

```bash
[Time]
NTP=dc.example.tld
```

### eJabberd XMPP Server

```bash
[Time]
NTP=dc.example.tld
```

### Postfix/Dovecot/Roundcube Mail Server

```bash
[Time]
NTP=dc.example.tld
```

Reiniciar el servicio cliente NTP de systemd.

```bash
systemctl restart systemd-timesyncd
```

Verificar el estado de la sincronización.

```bash
timedatectl status
journalctl --since -1h -u systemd-timesyncd
```

> **NOTA**: Es recomendable hacer coincidir la zona horaria de los `hosts` de acuerdo a la región en cuestión, ejecutando el comando `dpkg-reconfigure tzdata`. En plantillas de contenedores `Debian 9/10`, deben redefinirse los parámetros de idioma, mediante `dpkg-reconfigure locales` y luego de escoger el idioma de preferencia, ejecutar `locale-gen`, y reiniciar el `CT`. Para una mejor comprensión de los mensajes de error, se recomienda usar Inglés como el idioma predeterminado del sistema: `localectl set-locale LANG=en_US.utf8`.

## Instalación y configuración de Samba4 como AD DC

Las distribucións de Debian 9/10 cuentan en sus repositorios de paquetes con las versiones de Samba 4.5.16 y 4.9.5, respectivamente; las cuales no contienen algunas mejoras para la gestión de Unidades Organizativas mediante la herramienta `samba-tool`. Es por ello que se recomienda usar un repositorio de paquetes de la versión 4.9.6 o superior. En esta guía se usará el que proporciona el grupo francés [Tranquil IT Systems](http://samba.tranquil.it/debian/).

### Instalación de paquetes necesarios

Deshabilitar la interacción de configuración y proceder con la instalación de paquetes indispensables para la admnistración del sistema.

```bash
export DEBIAN_FRONTEND=noninteractive
apt install samba krb5-user winbind libnss-winbind net-tools bind9 dnsutils ldap-utils smbclient ldb-tools gnupg htop wget screen nmap telnet tcpdump rsync
unset DEBIAN_FRONTEND
```

### Preparación del aprovisionamiento

Detener y deshabilitar todos los servicios relacionados con Samba.

```bash
systemctl stop samba-ad-dc smbd nmbd winbind bind9
systemctl disable samba-ad-dc smbd nmbd winbind bind9
```

Opcionalmente se puede hacer una copia del archivo de configuración inicial de Samba ya que se sobrescribe durante el aprovisionamiento.

```bash
mv /etc/samba/smb.conf{,.org}
```

### Aprovisionamiento Samba Active Directory Domain Controller

Modo interactivo:

```bash
samba-tool domain provision --use-rfc2307 --interactive
```

Aceptar los valores por defecto a menos que se desee lo contrario.

Modo no interactivo:

```bash
samba-tool domain provision \
    --server-role=dc \
    --use-rfc2307 \
    --dns-backend=SAMBA_INTERNAL \
    --realm=EXAMPLE.TLD \
    --domain=EXAMPLE \
    --function-level=2008_R2 \
    --adminpass='P@s$w0rd.123'
```

Editar el fichero `/etc/samba/smb.conf` resultante.

```bash
nano /etc/samba/smb.conf

[global]
    dns forwarder = 127.0.0.1
    netbios name = DC
    realm = EXAMPLE.TLD
    server role = active directory domain controller
    server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
    server string = Samba4 %v AD DC
    workgroup = EXAMPLE
    idmap_ldb:use rfc2307 = yes
    ldap server require strong auth = no
    printing = bsd
    printcap name = /dev/null
[netlogon]
    path = /var/lib/samba/sysvol/example.tld/scripts
    read only = No
    create mask = 0700
    directory mask = 0644
[sysvol]
    path = /var/lib/samba/sysvol
    read only = No
    create mask = 0700
    directory mask = 0644
```

La directiva `ldap server require strong auth = no` en la sección `[global]` se utiliza para permitir el acceso por el puerto `tcp\389`.

Las directivas `create mask = 0700` y `directory mask = 0644` en las secciones `[netlogon]` y `[sysvol]` son para la correcta asignación de permisos tanto a ficheros como directorios.

### Configuración de Kerberos

Durante el aprovisionamiento, Samba crea un archivo de configuración con los valores necesarios para el correcto funcionamiento del AD DC.

Utilizar el fichero configuración de Kerberos generada durante el aprovisionamiento y editarlo.

```bash
mv /etc/krb5.conf{,.org}
ln -s /var/lib/samba/private/krb5.conf /etc/krb5.conf
```

```bash
nano /etc/krb5.conf

[libdefaults]
    default_realm = EXAMPLE.TLD
    dns_lookup_realm = false
    dns_lookup_kdc = true
[realms]
    EXAMPLE.TLD = {
        kdc = DC.EXAMPLE.TLD
        master_kdc = DC.EXAMPLE.TLD
        admin_server = DC.EXAMPLE.TLD
        default_domain = example.tld
    }
[domain_realm]
    .example.tld = EXAMPLE.TLD
    example.tld = EXAMPLE.TLD
[kdc]
    check-ticket-addresses = false
```

Iniciar, verificar el estado y habilitar el servicio de Samba AD DC.

```bash
systemctl unmask samba-ad-dc
systemctl start samba-ad-dc
systemctl status samba-ad-dc
systemctl enable samba-ad-dc
```

Evitar que la cuenta del usuario `Administrator` expire.

```bash
samba-tool user setexpiry Administrator --noexpiry
```

Reiniciar el servidor.

### Comprobaciones

Comprobar el nivel del dominio.

```bash
samba-tool domain level show
```

Comprobar la resolución del nombre de domino, `FQDN` y `hostname` por la dirección IP estática.

```bash
ping -c4 example.tld
ping -c4 dc.example.tld
ping -c4 dc
```

Solicitar ticket de Kerberos.

```bash
kinit Administrator@EXAMPLE.TLD
```

Listar tickets de Kerberos en caché.

```bash
klist
```

Listar recursos compartidos.

```bash
smbclient -L localhost -U%
```

Comprobar funcionamiento de la autenticación.

```bash
smbclient //localhost/netlogon -Uadministrator -c 'ls'
```

## Configuración del servidor Bind9 DNS

Durante el aprovisionamiento se utilizó el `dns-backend=SAMBA_INTERNAL`, que provee un servidor `DNS` interno del paquete `Samba`; aunque funcional en un entorno básico, tiene determinadas desventajas, como son la asignación de servidores `DNS forwarders` y una caché de resolución lenta. Para suplir estas carencias, se configurará `Bind9` integrándolo a `Samba`.

### Integración con Samba AD DC

Editar el fichero `/etc/samba/smb.conf` y en la sección `[global]`:

- añadir la directiva `nsupdate command = /usr/bin/nsupdate -g`,

- modificar la directiva `server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate` por `server services = -dns`,

- comentar ó eliminar la directiva `dns forwarder = 127.0.0.1`.

### Modificación del aprovisionamiento AD DC

Definir Bind9 como dns-backend.

```bash
mv /etc/bind/named.conf.local{,.org}
```

```bash
nano /etc/bind/named.conf.local

dlz "samba4" {
    database "dlopen /usr/lib/x86_64-linux-gnu/samba/bind9/dlz_bind9_10.so";
};
```

```bash
samba_upgradedns --dns-backend=BIND9_DLZ
chgrp bind /var/lib/samba/private/dns.keytab
chmod g+r /var/lib/samba/private/dns.keytab
touch /var/log/named.log
chown root:bind /var/log/named.log
chmod 664 /var/log/named.log
mv /etc/bind/named.conf.options{,.org}
```

```bash
nano /etc/bind/named.conf.options

options {
    version none;
    hostname none;
    server-id none;
    directory "/var/cache/bind";
    max-cache-size 10m;
    cleaning-interval 15;
    max-cache-ttl 60;
    max-ncache-ttl 60;
    forwarders { 8.8.8.8; 8.8.4.4; };
    forward first;
    dnssec-enable yes;
    dnssec-validation yes;
    dnssec-lookaside no;
    auth-nxdomain yes;
    listen-on-v6 { none; };
    tkey-gssapi-keytab "/var/lib/samba/private/dns.keytab";
    allow-query { 192.168.0.0/24; 127.0.0.1; };
    allow-recursion { 192.168.0.0/24; 127.0.0.1; };
    allow-update { 192.168.0.0/24; 127.0.0.1; };
    datasize default;
    empty-zones-enable no;
    minimal-responses yes;
};

logging {
    channel xfer-log {
        file "/var/log/named.log";
        print-category yes;
        print-severity yes;
        severity info;
    };
    category xfer-in { xfer-log; };
    category xfer-out { xfer-log; };
    category notify { xfer-log; };
};
```

```bash
mv /etc/default/bind9{,.org}
```

```bash
nano /etc/default/bind9

RESOLVCONF=no
OPTIONS="-4 -u bind"
```

```bash
nano /var/lib/samba/private/named.conf.update

grant *.example.tld wildcard *.0.168.192.in-addr.arpa. PTR TXT;
grant local-ddns zonesub any;
```

Reiniciar los servicios.

```bash
systemctl restart samba-ad-dc bind9
systemctl enable bind9
```

### Creación de zona inversa y registro PTR del servidor

```bash
samba-tool dns zonecreate localhost 0.168.192.in-addr.arpa -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost 0.168.192.in-addr.arpa 1 PTR 'dc.example.tld.' -U 'administrator'%'P@s$w0rd.123'
```

### Comprobaciones

Comprobar correcta ejecución del servidor Bind9 DNS.

```bash
netstat -tapn | grep 53
netstat -lptun
```

Comprobar registros DNS necesarios para el funcionamiento correcto de Samba AD DC.

```bash
dig example.tld
dig -x 192.168.0.1 @127.0.0.1 +short
host -t A dc.example.tld
host -t SRV _kerberos._udp.example.tld
host -t SRV _ldap._tcp.example.tld
```

Comprobar actualización automática de los registros DNS.

```bash
samba-tool dns query 127.0.0.1 example.tld @ ALL -U 'administrator'%'P@s$w0rd.123'
samba_dnsupdate --verbose --all-names
```

## Configuración del servidor NTP

El servidor Samba AD DC actuará como servidor de tiempo (Network Time Protocol Server - NTP Server) propiciando la sincronización de los relojes de los hosts y sistemas informáticos existentes en su entorno de red.

### Integración con Samba AD DC

#### NTPd

Instalar paquetes necesarios.

```bash
apt install ntpdate ntp
```

Configurar el servicio.

```bash
mv /etc/ntp.conf{,.org}
```

```bash
nano /etc/ntp.conf

driftfile /var/lib/ntp/ntp.drift
logfile /var/log/ntpd.log
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable
server 127.127.1.0
fudge 127.127.1.0 stratum 10
server ntp.tld iburst prefer
ntpsigndsocket /var/lib/samba/ntp_signd
restrict -4 default kod notrap nomodify nopeer noquery mssntp
restrict default mssntp
restrict 192.168.0.0 mask 255.255.255.0 nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
restrict source notrap nomodify noquery
broadcast 192.168.0.255 ttl 4
broadcastdelay 0.004
tinker panic 0
```

Establecer permisos.

```bash
chgrp ntp /var/lib/samba/ntp_signd
usermod -a -G staff ntp
```

Reiniciar el servicio.

```bash
systemctl restart ntp
```

### Comprobaciones

```bash
systemctl status ntp
ntpdate -vqd ntp.tld
ntpq -p
```

#### Chronyd

Instalar paquetes necesarios.

```bash
apt install chrony
```

Configurar el servicio.

```bash
mv /etc/chrony.conf{,.org}
```

```bash
nano /etc/chrony.conf

pool ntp.tld iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
allow 192.168.0.0/24
local stratum 10
keyfile /etc/chrony.keys
leapsectz right/UTC
logdir /var/log/chrony
ntpsigndsocket /var/lib/samba/ntp_signd
```

Establecer permisos.

```bash
chgrp chrony /var/lib/samba/ntp_signd
chmod 750 /var/lib/samba/ntp_signd/
```

Reiniciar el servicio.

```bash
systemctl restart chronyd
```

### Comprobaciones

```bash
systemctl status chronyd
chronyc sources
```

## Configuración del servidor DHCP

Instalar el paquete `isc-dhcp-server` para asignar direcciones `IP` a los `hosts` clientes, permitiendo la actualización dinámica de sus registros `DNS` tanto para la zona directa como la inversa.

```bash
apt install isc-dhcp-server
```

> **NOTA**: Este método puede afectar funcionalidades en los clientes `Windows`, los cuales tratarán de actualizar los registros `DNS` por sí mismos, utilizando sus cuentas de `hosts`. Para evitar este comportamiento, debe crearse una Política de Grupo y aplicarla a Unidades Organizativas que contengan equipos.
>
> La `GPO` debe configurarse con los siguientes parámetros:

```cmd
Computer Configuration
  Policies
    Administrative Templates
      Network
        DNS Client
          Dynamic Update = Disabled
          Register PTR Records = Disabled
```

### Integración con Samba AD DC

Crear un usuario no privilegiado, pero otorgándole permisos de administración sobre el servidor `DNS`. Aunque no es obligatorio, es recomendable inhabilitar el tiempo de expiración de la contraseña.

```bash
samba-tool user create dhcp --description='Unprivileged DHCP Server user account' --random-password
samba-tool user setexpiry dhcp --noexpiry
samba-tool group addmembers 'DnsAdmins' dhcp
```

Exportar las credenciales del usuario a un archivo `keytab`, y asignar permisos necesarios.

```bash
samba-tool domain exportkeytab --principal=dhcp@EXAMPLE.TLD /etc/dhcp/dhcpd.keytab
chown root:root /etc/dhcp/dhcpd.keytab
chmod 400 /etc/dhcp/dhcpd.keytab
```

### Integración con Bind9 DNS

Crear el fichero `/etc/dhcp/dhcpd-update-samba-dns.conf`, que contendrá las variables a utilizarse para la actualización de los registros `DNS`.

```bash
nano /etc/dhcp/dhcpd-update-samba-dns.conf

# Variables
KRB5CC="/run/dhcpd.krb5cc"
KEYTAB="/etc/dhcp/dhcpd.keytab"
DOMAIN="example.tld"
REALM="EXAMPLE.TLD"
PRINCIPAL="dhcp@${REALM}"
NAMESERVER="dc.${DOMAIN}"
ZONE="${DOMAIN}"
```

Crear los `scripts` de actualización de los registros `DNS`.

```bash
nano /etc/dhcp/dhcpd-update-dns.sh

#!/bin/bash
# Begin dhcpd-update-dns.sh

. /etc/dhcpd/dhcpd-update-samba-dns.conf || exit 1

ACTION=$1
IP=$2
HNAME=$3

export KRB5CC KEYTAB DOMAIN REALM PRINCIPAL NAMESERVER ZONE ACTION IP HNAME

/usr/bin/samba-dnsupdate.sh -m &

# End dhcpd-update-samba-dns.sh
```

```bash
nano /usr/bin/samba-dnsupdate.sh

#!/bin/bash
# Begin samba-dnsupdate.sh
# Author: DJ Lucas <dj_AT_linuxfromscratch_DOT_org>
# kerberos_creds() courtesy of Sergey Urushkin
# http://www.kuron-germany.de/michael/blog/wp-content/uploads/2012/03/dhcpdns-sergey2.txt

# DHCP server should be authoritative for its own records, sleep for 5 seconds
# to allow unconfigured Windows hosts to create their own DNS records
# In order to use this script you should disable dynamic updates by hosts that
# will receive addresses from this DHCP server. Instructions are found here:
# https://wiki.archlinux.org/index.php/Samba_4_Active_Directory_Domain_Controller#DHCP
sleep 5

checkvalues()
{
        [ -z "${2}" ] && echo "Error: argument '${1}' requires a parameter." && exit 1

        case ${2} in

                -*)
                        echo "Error: Invalid parameter '${2}' passed to ${1}."
                        exit 1
                ;;

                *)
                        return 0
                ;;
        esac
}

showhelp()
{
echo -e "\n"`basename ${0}` "uses samba-tool to update DNS records in Samba 4's DNS"
echo "server when using INTERNAL DNS or BIND9 DLZ plugin."
echo ""
echo "    Command line options (and variables):"
echo ""
echo "      -a | --action      Action for this script to perform"
echo "                         ACTION={add|delete}"
echo "      -c | --krb5cc      Path of the krb5 credential cache (optional)"
echo "                         Default: KRB5CC=/run/dhcpd.krb5cc"
echo "      -d | --domain      The DNS domain/zone to be updated"
echo "                         DOMAIN={domain.tld}"
echo "      -h | --help        Show this help message and exit"
echo "      -H | --hostname    Hostname of the record to be updated"
echo "                         HNAME={hostname}"
echo "      -i | --ip          IP address of the host to be updated"
echo "                         IP={0.0.0.0}"
echo "      -k | --keytab      Krb5 keytab to be used for authorization (optional)"
echo "                         Default: KEYTAB=/etc/dhcp/dhcpd.keytab"
echo "      -m | --mitkrb5     Use MIT krb5 client utilities"
echo "                         MITKRB5={YES|NO}"
echo "      -n | --nameserver  DNS server to be updated (must use FQDN, not IP)"
echo "                         NAMESERVER={server.internal.domain.tld}"
echo "      -p | --principal   Principal used for DNS updates"
echo "                         PRINCIPAL={user@domain.tld}"
echo "      -r | --realm       Authentication realm"
echo "                         REALM={DOMAIN.TLD}"
echo "      -z | --zone        Then name of the zone to be updated in AD."
echo "                         ZONE={zonename}"
echo ""
echo "Example: $(basename $0) -d domain.tld -i 192.168.0.x -n 192.168.0.x \\"
echo "             -r DOMAIN.TLD -p user@domain.tld -H HOSTNAME -m"
echo ""
}

# Process arguments
[ -z "$1" ] && showhelp && exit 1
while [ -n "$1" ]; do
        case $1 in

                -a | --action)
                        checkvalues ${1} ${2}
                        ACTION=${2}
                        shift 2
                ;;

                -c | --krb5cc)
                        checkvalues ${1} ${2}
                        KRB5CC=${2}
                        shift 2
                ;;

                -d | --domain)
                        checkvalues ${1} ${2}
                        DOMAIN=${2}
                        shift 2
                ;;

                -h | --help)
                        showhelp
                        exit 0
                ;;

                -H | --hostname)
                        checkvalues ${1} ${2}
                        HNAME=${2%%.*}
                        shift 2
                ;;

                -i | --ip)
                        checkvalues ${1} ${2}
                        IP=${2}
                        shift 2
                ;;

                -k | --keytab)
                        checkvalues ${1} ${2}
                        KEYTAB=${2}
                        shift 2
                ;;

                -m | --mitkrb5)
                        KRB5MIT=YES
                        shift 1
                ;;

                -n | --nameserver)
                        checkvalues ${1} ${2}
                        NAMESERVER=${2}
                        shift 2
                ;;

                -p | --principal)
                        checkvalues ${1} ${2}
                        PRINCIPAL=${2}
                        shift 2
                ;;

                -r | --realm)
                        checkvalues ${1} ${2}
                        REALM=${2}
                        shift 2
                ;;

                -z | --zone)
                        checkvalues ${1} ${2}
                        ZONE=${2}
                        shift 2
                ;;

                *)
                        echo "Error!!! Unknown command line opion!"
                        echo "Try" `basename $0` "--help."
                        exit 1
                ;;
        esac
done

# Sanity checking
[ -z "$ACTION" ] && echo "Error: action not set." && exit 2
case "$ACTION" in
        add | Add | ADD)
                ACTION=ADD
        ;;
        del | delete | Delete | DEL | DELETE)
                ACTION=DEL
        ;;
        *)
                echo "Error: invalid action \"$ACTION\"." && exit 3
        ;;
esac
[ -z "$KRB5CC" ] && KRB5CC=/run/dhcpd.krb5cc
[ -z "$DOMAIN" ] && echo "Error: invalid domain." && exit 4
[ -z "$HNAME" ] && [ "$ACTION" == "ADD" ] && \
     echo "Error: hostname not set." && exit 5
[ -z "$IP" ] && echo "Error: IP address not set." && exit 6
[ -z "$KEYTAB" ] && KEYTAB=/etc/dhcp/dhcpd.keytab
[ -z "$NAMESERVER" ] && echo "Error: nameservers not set." && exit 7
[ -z "$PRINCIPAL" ] && echo "Error: principal not set." && exit 8
[ -z "$REALM" ] && echo "Error: realm not set." && exit 9
[ -z "$ZONE" ] && echo "Error: zone not set." && exit 10

# Disassemble IP for reverse lookups
OCT1=$(echo $IP | cut -d . -f 1)
OCT2=$(echo $IP | cut -d . -f 2)
OCT3=$(echo $IP | cut -d . -f 3)
OCT4=$(echo $IP | cut -d . -f 4)
RZONE="$OCT3.$OCT2.$OCT1.in-addr.arpa"

kerberos_creds() {
export KRB5_KTNAME="$KEYTAB"
export KRB5CCNAME="$KRB5CC"

if [ "$KRB5MIT" = "YES" ]; then
    KLISTARG="-s"
else
    KLISTARG="-t"
fi

klist $KLISTARG || kinit -k -t "$KEYTAB" -c "$KRB5CC" "$PRINCIPAL" || { logger -s -p daemon.error -t dhcpd kinit for dynamic DNS failed; exit 11; }
}


add_host(){
    logger -s -p daemon.info -t dhcpd Adding A record for host $HNAME with IP $IP to zone $ZONE on server $NAMESERVER
    samba-tool dns add $NAMESERVER $ZONE $HNAME A $IP -k yes
}


delete_host(){
    logger -s -p daemon.info -t dhcpd Removing A record for host $HNAME with IP $IP from zone $ZONE on server $NAMESERVER
    samba-tool dns delete $NAMESERVER $ZONE $HNAME A $IP -k yes
}


update_host(){
    logger -s -p daemon.info -t dhcpd Removing A record for host $HNAME with IP $CURIP from zone $ZONE on server $NAMESERVER
    samba-tool dns delete $NAMESERVER $ZONE $HNAME A $CURIP -k yes
    add_host
}


add_ptr(){
    logger -s -p daemon.info -t dhcpd Adding PTR record $OCT4 with hostname $HNAME to zone $RZONE on server $NAMESERVER
    samba-tool dns add $NAMESERVER $RZONE $OCT4 PTR $HNAME.$DOMAIN -k yes
}


delete_ptr(){
    logger -s -p daemon.info -t dhcpd Removing PTR record $OCT4 with hostname $HNAME from zone $RZONE on server $NAMESERVER
    samba-tool dns delete $NAMESERVER $RZONE $OCT4 PTR $HNAME.$DOMAIN -k yes
}


update_ptr(){
    logger -s -p daemon.info -t dhcpd Removing PTR record $OCT4 with hostname $CURHNAME from zone $RZONE on server $NAMESERVER
    samba-tool dns delete $NAMESERVER $RZONE $OCT4 PTR $CURHNAME -k yes
    add_ptr
}

case "$ACTION" in
    ADD)
        kerberos_creds
        host -t A $HNAME.$DOMAIN > /dev/null
        if [ "${?}" == 0 ]; then
          CURIP=$(host -t A $HNAME.$DOMAIN | cut -d " " -f 4 )
          if [[ "$CURIP" != "$IP" ]]; then
             update_host
          fi
        else
           add_host
        fi

        host -t PTR $IP > /dev/null
        if [ "${?}" == 0 ]; then
           CURHNAME=$(host -t PTR $IP | cut -d " " -f 5 | rev | cut -c 2- | rev)
           if [[ "$CURHNAME" != "$HNAME.$DOMAIN" ]]; then
              update_ptr
           fi
        else
           add_ptr
        fi
    ;;

    DEL)
        kerberos_creds
        host -t A $HNAME.$DOMAIN > /dev/null
        if [ "${?}" == 0 ]; then
            delete_host
        fi

        host -t PTR $IP > /dev/null
        if [ "${?}" == 0 ]; then
            delete_ptr
        fi
    ;;

    *)
        echo "Error: Invalid action '$ACTION'!" && exit 12
    ;;
esac

# End samba-dnsupdate.sh
```

Asignar permisos de ejecución.

```bash
chmod +x /etc/dhcp/dhcpd-update-dns.sh /usr/bin/samba-dnsupdate.sh
```

Crear fichero principal del servicio `DHCP`.

```bash
mv /etc/dhcp/dhcpd.conf{,.org}
```

```bash
nano /etc/dhcp/dhcpd.conf

authoritative;
server-identifier 192.168.0.1;
ddns-update-style none;
deny declines;
deny bootp;
deny duplicates;
log-facility local7;

shared-network EXAMPLE {
  subnet 192.168.0.0 netmask 255.255.255.0 {
    range 192.168.0.200 192.168.0.250;
    option domain-name "example.tld";
    option domain-name-servers 192.168.0.1;
    option routers 192.168.0.254;
    option subnet-mask 255.255.255.0;
    option broadcast-address 192.168.0.255;
    option netbios-name-servers 192.168.0.1;
    option netbios-node-type 8;
    option ntp-servers 192.168.0.1;
    option time-offset -18000;
    do-forward-updates false;
    ignore client-updates;
    update-static-leases false;
    one-lease-per-client true;
    update-conflict-detection false;
    deny client-updates;
    default-lease-time 86400;
    max-lease-time 86400;
    on commit {
      set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
      set ClientName = pick-first-value(option host-name, host-decl-name);
      execute("/etc/dhcp/dhcpd-update-dns.sh", "add", ClientIP, ClientName);
    }
    on release {
      set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
      set ClientName = pick-first-value(option host-name, host-decl-name);
      execute("/etc/dhcp/dhcpd-update-dns.sh", "delete", ClientIP, ClientName);
    }
    on expiry {
      set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
      set ClientName = pick-first-value(option host-name, host-decl-name);
      execute("/etc/dhcp/dhcpd-update-dns.sh", "delete", ClientIP, ClientName);
    }
  }
}
```

> **NOTA**: Esta configuración asignará direcciones `IP` y actualizará los registros `DNS` para todos los `hosts` que se conecten a la red y que tengan habilitada la obtención de parámetros de red vía `DHCP`.

Si solo se quisiera asignar parámetros de red a los `hosts` que realmente forman parte de la organización, se puede usar la funcionalidad de clases y subclases, ejemplo:

```bash
class "allocation-class-1" {
  match pick-first-value (option dhcp-client-identifier, hardware);
}
subclass "allocation-class-1" 1:08:00:27:aa:70:37;
subclass "allocation-class-1" 1:08:00:27:9f:ff:05;
pool {
  range 192.168.0.200 192.168.0.250;
  allow members of "allocation-class-1";
}
```

Otra forma sería definiendo asignaciones estáticas, ejemplo:

```bash
pool {
  range 192.168.0.200 192.168.0.250;
  deny unknown-clients;
  group {
    host pc-client1 {
      hardware ethernet 08:00:27:aa:70:37;
      fixed-address 192.168.0.200;
    }
    host pc-client2 {
      hardware ethernet 08:00:27:9f:ff:05;
      fixed-address 192.168.0.201;
    }
  }
}
```

También se puede usar la combinación de ambas técnicas, ejemplo:

```bash
class "allocation-class-1" {
  match pick-first-value (option dhcp-client-identifier, hardware);
}
subclass "allocation-class-1" 1:08:00:27:aa:70:37;
subclass "allocation-class-1" 1:08:00:27:9f:ff:05;
pool {
  range 192.168.0.200 192.168.0.250;
  allow members of "allocation-class-1";
  deny unknown-clients;
  group {
    host pc-client1 {
      hardware ethernet 08:00:27:aa:70:37;
      fixed-address 192.168.0.200;
    }
    host pc-client2 {
      hardware ethernet 08:00:27:9f:ff:05;
      fixed-address 192.168.0.201;
    }
  }
}
```

Idependientemente del método que se adopte, deben conocerse de antemano las direcciones `MAC` de los `hosts`, y establecer la asignación de parámetros de red dentro de la subcláusula `subnet {}` y el rango de direcciones `IP` a asignar, debe estar contenido dentro de la subcláusula `pool {}`, ejemplo:

```bash
nano /etc/dhcp/dhcpd.conf

authoritative;
server-identifier 192.168.0.1;
ddns-update-style none;
deny declines;
deny bootp;
deny duplicates;
log-facility local7;

shared-network EXAMPLE {
  subnet 192.168.0.0 netmask 255.255.255.0 {
    option domain-name "example.tld";
    option domain-name-servers 192.168.0.1;
    option routers 192.168.0.254;
    option subnet-mask 255.255.255.0;
    option broadcast-address 192.168.0.255;
    option netbios-name-servers 192.168.0.1;
    option netbios-node-type 8;
    option ntp-servers 192.168.0.1;
    option time-offset -18000;
    do-forward-updates false;
    ignore client-updates;
    update-static-leases false;
    one-lease-per-client true;
    update-conflict-detection false;
    deny client-updates;
    default-lease-time 86400;
    max-lease-time 86400;
    class "allocation-class-1" {
      match pick-first-value (option dhcp-client-identifier, hardware);
    }
    subclass "allocation-class-1" 1:08:00:27:aa:70:37;
    subclass "allocation-class-1" 1:08:00:27:9f:ff:05;
    pool {
      range 192.168.0.200 192.168.0.250;
      allow members of "allocation-class-1";
      deny unknown-clients;
      group {
        host pc-client1 {
          hardware ethernet 08:00:27:aa:70:37;
          fixed-address 192.168.0.200;
        }
        host pc-client2 {
          hardware ethernet 08:00:27:9f:ff:05;
          fixed-address 192.168.0.201;
        }
      }
    }
    on commit {
      set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
      set ClientName = pick-first-value(option host-name, host-decl-name);
      execute("/etc/dhcp/dhcpd-update-dns.sh", "add", ClientIP, ClientName);
    }
    on release {
      set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
      set ClientName = pick-first-value(option host-name, host-decl-name);
      execute("/etc/dhcp/dhcpd-update-dns.sh", "delete", ClientIP, ClientName);
    }
    on expiry {
      set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
      set ClientName = pick-first-value(option host-name, host-decl-name);
      execute("/etc/dhcp/dhcpd-update-dns.sh", "delete", ClientIP, ClientName);
    }

  }
}
```

### Comprobaciones

Reiniciar el servicio y observar las salidas generadas en el fichero de trazas `/var/log/syslog`.

```bash
systemctl restart isc-dhcp-server
tail -fn100 /var/log/syslog
```

> **NOTA**: Se puede verificar la configuración del servidor `DHCP`, ejecutando el comando `dhcpd -t`.

## Creación de Unidades Organizativas, Grupos y Cuentas de Usuarios

Las unidades organizativas son subdivisiones jerárquicas que agrupan entidades, tales como otras OUs, cuentas y grupos de usuarios, y ordenadores; facilitando la aplicación de políticas de grupos en un AD DC.

### Creación de Unidades Organizativas (Organizational Units - OU)

Crear nueva Unidad Organizativa.

```bash
samba-tool ou create 'OU=ACME,DC=example,DC=tld' --description='EXAMPLE.TLD Main Organizational Unit'
```

Crear la Unidad Organizativa `Workstations` para agrupar las estaciones de trabajo, perteneciente a `ACME`.

```bash
samba-tool ou create 'OU=Workstations,OU=ACME,DC=example,DC=tld' --description='Workstations Organizational Unit'
```

> **NOTA**: A medida que se vayan incorporando estaciones de trabajo al dominio, deben ser movidas hacia esta Unidad Organizativa, ejecutando el comando `samba-tool computer move computername <new_ou_dn>` ó utilizando la aplicación gráfica `Active Directory Users and Computers` disponible en el paquete de herramientas administrativas `RSAT`. Ejemplo:

```bash
samba-tool computer move PC-CLIENT1$ 'OU=Workstations,OU=ACME,DC=example,DC=tld'
```

### Creación de Grupos

Crear nuevo Grupo de Usuarios perteneciente a la OU `ACME`.

```bash
samba-tool group add IT --groupou='OU=ACME' --description='IT Technical Support Group'
```

### Creación de Cuentas de Usuarios

Crear nueva Cuenta de Usuario perteneciente a la OU `ACME`.

```bash
samba-tool user create 'john.doe' 'P@s$w0rd.456' \
    --userou='OU=ACME' \
    --surname='Doe' \
    --given-name='John' \
    --initials='JD' \
    --job-title='Network Administrator' \
    --department='IT' \
    --company='EXAMPLE' \
    --description='IT Technical Support Account' \
    --mail='john.doe@example.tld'
```

Añadir nuevo usuario al grupo `IT`.

```bash
samba-tool group addmembers 'IT' john.doe
```

Añadir nuevo usuario a los grupos administrativos del AD DC.

```bash
samba-tool group addmembers 'Administrators' john.doe
samba-tool group addmembers 'Domain Admins' john.doe
samba-tool group addmembers 'Schema Admins' john.doe
samba-tool group addmembers 'Enterprise Admins' john.doe
samba-tool group addmembers 'Group Policy Creator Owners' john.doe
```

## Creación de Políticas de Grupos (Group Policy Object - GPO)

En los sistemas operativos Windows, una Política de Grupo (`Group Policy Object - GPO`) es un conjunto de configuraciones que define cómo será la apariencia y el comportamiento del sistema, para usuarios y/ó grupos de usuarios y ordenadores, previamente definidos y agrupados en `OUs`.

Configurar almacén central para definiciones de directivas.

```bash
tar -xzmf PolicyDefinitions.tar.gz -C /var/lib/samba/sysvol/example.tld/Policies/
chown -R 3000004.3000004 /var/lib/samba/sysvol/example.tld/Policies/
```

> **NOTA**: El fichero [PolicyDefinitions.tar.gz](confs/addc/PolicyDefinitions.tar.gz) contine definiciones de directivas compatibles con sistemas operativos Windows hasta la versión 1809 de Windows 10. También están incorporadas las definiciones para el navegador Mozilla Firefox versión 60 y superiores; así como el cliente de correo electrónico Thunderbird versión 68 y superiores.

Crear Política de Grupo para actualizaciones dinámicas `DHCP/DNS`.

```bash
samba-tool gpo create 'DHCP with dynamic DNS updates Policy' -U 'administrator'%'P@s$w0rd.123'
```

Vincular `GPO` a Unidad Organizativa `Workstations`.

```bash
samba-tool gpo setlink 'OU=Workstations,OU=ACME,DC=example,DC=tld' {4E8A2506-32E1-4E66-B5A4-362B4ACD0DF0} -U 'administrator'%'P@s$w0rd.123'
```

### Comprobaciones

```bash
samba-tool gpo listall
samba-tool gpo listcontainers {4E8A2506-32E1-4E66-B5A4-362B4ACD0DF0} -U 'administrator'%'P@s$w0rd.123'
samba-tool gpo getlink 'OU=Workstations,OU=ACME,DC=example,DC=tld' -U 'administrator'%'P@s$w0rd.123'
```

> **NOTA**: La modificación de los parámetros de las Políticas de Grupo se debe realizar mediante la aplicación gráfica `Group Policy Management` disponible en el paquete de herramientas administrativas `RSAT`.

## Instalación y configuración de Squid Proxy e integración con Samba AD DC

Crear registros DNS.

```bash
samba-tool dns add localhost example.tld proxy A '192.168.0.2' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost 0.168.192.in-addr.arpa 2 PTR 'proxy.example.tld.' -U 'administrator'%'P@s$w0rd.123'
```

Crear nueva Unidad Organizativa `Proxy` para grupos de navegación, perteneciente a `ACME`.

```bash
samba-tool ou create 'OU=Proxy,OU=ACME,DC=example,DC=tld' --description='Proxy Groups Organizational Unit'
```

Crear nuevos grupos de navegación pertenecientes a la OU `Proxy`.

```bash
samba-tool group add Intranet --groupou='OU=Proxy,OU=ACME' --description='.CU Access Group'
samba-tool group add Internet --groupou='OU=Proxy,OU=ACME' --description='Internet Access Group'
samba-tool group add Unrestricted --groupou='OU=Proxy,OU=ACME' --description='Unrestricted Access Group'
```

Crear nuevos usuarios de navegación pertenecientes a la OU `ACME`.

```bash
samba-tool user create 'sheldon' 'Amy*123' \
    --userou='OU=ACME' \
    --surname='Cooper' \
    --given-name='Sheldon' \
    --department='PHYSICS' \
    --company='EXAMPLE' \
    --description='Intranet Access Account' \
    --mail='sheldon@example.tld'
```

```bash
samba-tool user create 'leonard' 'Penny*456' \
    --userou='OU=ACME' \
    --surname='Hofstadter' \
    --given-name='Leonard' \
    --department='PSYCHOLOGY' \
    --company='EXAMPLE' \
    --description='Internet Access Account' \
    --mail='leonard@example.tld'
```

```bash
samba-tool user create 'rajesh' 'Howard*789' \
    --userou='OU=ACME' \
    --surname='Koothrappali' \
    --given-name='Rajesh' \
    --department='ASTROLOGY' \
    --company='EXAMPLE' \
    --description='Unrestricted Access Account' \
    --mail='rajesh@example.tld'
```

Añadir usuarios a los grupos creados.

```bash
samba-tool group addmembers 'Intranet' sheldon
samba-tool group addmembers 'Internet' leonard
samba-tool group addmembers 'Unrestricted' rajesh
```

### Instalación de paquetes necesarios

```bash
export DEBIAN_FRONTEND=noninteractive
apt install squid krb5-user msktutil libsasl2-modules-gssapi-mit
unset DEBIAN_FRONTEND
```

Detener el servicio y remplazar el fichero de configuración por defecto de Squid.

```bash
systemctl stop squid
mv /etc/squid/squid.conf{,.org}
nano /etc/squid/squid.conf
```

Configuración de `Kerberos`.

```bash
mv /etc/krb5.conf{,.org}
```

```bash
nano /etc/krb5.conf

[libdefaults]
    default_realm = EXAMPLE.TLD
    dns_lookup_realm = false
    dns_lookup_kdc = true
    clockskew = 3600
    ticket_lifetime = 24h
    forwardable = yes
    default_keytab_name = /etc/krb5.keytab
[realms]
    EXAMPLE.TLD = {
        kdc = DC.EXAMPLE.TLD:88
        master_kdc = DC.EXAMPLE.TLD
        admin_server = DC.EXAMPLE.TLD:749
        default_domain = example.tld
    }
[domain_realm]
    .example.tld = EXAMPLE.TLD
    example.tld = EXAMPLE.TLD
```

Generar archivo keytab.

```bash
kinit Administrator@EXAMPLE.TLD
msktutil -c -b "CN=Computers" \
    -s HTTP/proxy.example.tld \
    -h proxy.example.tld \
    -k /etc/krb5.keytab \
    --computer-name PROXY \
    --upn HTTP/proxy.example.tld \
    --server dc.example.tld \
    --verbose
```

Establecer los permisos del archivo `keytab`.

```bash
chown root:proxy /etc/krb5.keytab
chmod 640 /etc/krb5.keytab
```

Comprobar que `Kerberos` funciona.

```bash
kinit -k HTTP/proxy.example.tld
klist
```

Comprobar que la cuenta de host se actualice correctamente.

```bash
msktutil --auto-update --verbose --computer-name proxy
```

Agregar en `crontab`.

```bash
nano /etc/crontrab

59 23 * * * root msktutil --auto-update --verbose --computer-name proxy > /dev/null 2>&1
```

### Integración con Samba AD DC

Crear nueva Cuenta de Usuario para el servicio `squid`.

Esta cuenta sería usada para propiciar la autenticación básica LDAP en caso de fallar Kerberos ó para uso de gestores de descargas no compatibles con Kerberos ó en aquellas estaciones que no están unidas al dominio.

```bash
samba-tool user create 'squid' 'P@s$w0rd.789' \
    --surname='Proxy Service' \
    --given-name='Squid' \
    --company='EXAMPLE' \
    --description='Squid Proxy Service Account'
samba-tool user setexpiry squid --noexpiry
```

Editar el fichero `/etc/squid/squid.conf` y agregar los métodos de autenticación.

```bash
nano /etc/squid/squid.conf

# OPTIONS FOR AUTHENTICATION
# ---------------------------------------------------------------------
# Kerberos authentication
auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -r -d -s HTTP/proxy.example.tld@EXAMPLE.TLD -k /etc/krb5.keytab
auth_param negotiate children 20 startup=0 idle=1
auth_param negotiate keep_alive off

# Basic LDAP authentication (fallback)
auth_param basic program /usr/lib/squid/basic_ldap_auth -R -b "dc=example,dc=tld" -D squid@example.tld -w "P@s$w0rd.789" -f (|(userPrincipalName=%s)(sAMAccountName=%s)) -h dc.example.tld
auth_param basic children 10
auth_param basic realm PROXY.EXAMPLE.TLD
auth_param basic credentialsttl 8 hours

# ACCESS CONTROL LISTS
# ---------------------------------------------------------------------
acl CUBA dstdomain .cu
acl AUTH proxy_auth REQUIRED

# Kerberos group mapping
external_acl_type INTRANET ttl=300 negative_ttl=60 %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g Intranet -D EXAMPLE.TLD
external_acl_type INTERNET ttl=300 negative_ttl=60 %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g Internet -D EXAMPLE.TLD
external_acl_type UNRESTRICTED ttl=300 negative_ttl=60 %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g Unrestricted -D EXAMPLE.TLD
acl intranet external INTRANET
acl internet external INTERNET
acl unrestricted external UNRESTRICTED

# LDAP group mapping
external_acl_type memberof %LOGIN /usr/lib/squid/ext_ldap_group_acl -R -K -S -b "dc=example,dc=tld" -D squid@example.tld -w "P@s$w0rd.789" -f "(&(objectClass=person)(sAMAccountName=%v)(memberof=cn=%g,ou=Proxy,ou=ACME,dc=example,dc=tld))" -h dc.example.tld
acl LDAPintranet external memberof Intranet
acl LDAPinternet external memberof Internet
acl LDAPunrestricted external memberof Unrestricted

# HTTP_ACCESS
# ---------------------------------------------------------------------
http_access deny !AUTH
# Using Kerberos
http_access allow localnet unrestricted
http_access allow localnet internet !blacklisted_sites
http_access allow localnet intranet CUBA
# Using basic LDAP
http_access allow localnet LDAPunrestricted
http_access allow localnet LDAPinternet !blacklisted_sites
http_access allow localnet LDAPintranet CUBA
http_access deny all
```

### Comprobaciones

Usando autenticación `Kerberos`.

```bash
/usr/lib/squid/ext_kerberos_ldap_group_acl -a -g Internet -D EXAMPLE.TLD
```

Usando autenticación básica LDAP.

```bash
/usr/lib/squid/basic_ldap_auth -R -b "dc=example,dc=tld" -D squid@example.tld -w "P@s$w0rd.789" -f sAMAccountName=%s -h dc.example.tld
```

Membresía de grupos LDAP.

```bash
/usr/lib/squid/ext_ldap_group_acl -R -K -S -b "dc=example,dc=tld" \
    -D squid@example.tld -w "P@s$w0rd.789" \
    -f "(&(objectClass=person)(sAMAccountName=%v)\
        (memberof=cn=%g,ou=Proxy,ou=ACME,dc=example,dc=tld))" \
    -h dc.example.tld
```

Analizando trazas de navegación.

```bash
tail -fn100 /var/log/squid/access.log
```

## Instalación y configuración de eJabberd XMPP Server e integración con Samba AD DC

### Instalación de paquetes necesarios

```bash
apt install ejabberd ejabberd-contrib erlang-eldap
```

Crear certificado de seguridad TLS/SSL.

```bash
mv /etc/ejabberd/ejabberd.pem{,.org}
```

Para Debian 9 Stretch.

```bash
openssl req -x509 -nodes -days 3650 -sha512 \
    -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=example.tld/emailAddress=postmaster@example.tld/" \
    -reqexts SAN -extensions SAN \-config <(cat /etc/ssl/openssl.cnf \
        <(printf "\n[SAN]\nsubjectAltName=DNS:jb.example.tld,\
        DNS:conference.example.tld,DNS:echo.example.tld,\
        DNS:pubsub.example.tld,IP:192.168.0.3")) \
    -newkey rsa:4096 \
    -out /tmp/exampleJabber.crt \
    -keyout /tmp/exampleJabber.key
openssl dhparam -out /etc/ssl/dh2048.pem 2048
```

Para Debian 10 Buster.

```bash
openssl req -x509 -nodes -days 3650 -sha512 \
    -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=example.tld/emailAddress=postmaster@example.tld/" \
    -addext "subjectAltName = DNS:jb.example.tld,DNS:conference.example.tld,DNS:echo.example.tld,DNS:pubsub.example.tld,IP:192.168.0.3" \
    -newkey rsa:4096 \
    -out /tmp/exampleJabber.crt \
    -keyout /tmp/exampleJabber.key
openssl dhparam -out /etc/ssl/dh2048.pem 2048
```

```bash
cat /tmp/{exampleJabber.crt,exampleJabber.key} > /etc/ejabberd/ejabberd.pem
chmod 0640 /etc/ejabberd/ejabberd.pem
chown root:ejabberd /etc/ejabberd/ejabberd.pem
```

Comprobar correcta creación del certificado.

```bash
openssl x509 -in /etc/ejabberd/ejabberd.pem -text -noout
```

Definir el nombre de dominio del servidor `eJabberd` y parámetros de seguridad TLS/SSL en la comunicación c2s (cliente-servidor).

```bash
cp /etc/ejabberd/ejabberd.yml{,.org}
nano /etc/ejabberd/ejabberd.yml
```

Para Debian 9 Stretch.

```yml
hosts:
  - "example.tld"
listen:
  -
    port: 5222
    ip: "::"
    module: ejabberd_c2s
    certfile: "/etc/ejabberd/ejabberd.pem"
    starttls: true
    protocol_options:
      - "no_sslv3"
      - "no_sslv2"
      - "no_tlsv1"
      - "no_tlsv1_1"
    ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
        ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
        ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:\
        ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:\
        ECDHE-RSA-AES128-SHA256"
    max_stanza_size: 65536
    shaper: c2s_shaper
    access: c2s
    zlib: true
    resend_on_timeout: if_offline
    tls_compression: false
    starttls_required: true
    dhfile: "/etc/ssl/dh2048.pem"
disable_sasl_mechanisms: "digest-md5"
```

Para Debian 10 Buster.

```yml
hosts:
  - "example.tld"
certfiles:
  - "/etc/ejabberd/ejabberd.pem"
define_macro:
  'TLS_CIPHERS': "HIGH:!aNULL:!eNULL:!3DES:@STRENGTH"
  'TLS_OPTIONS':
    - "no_sslv3"
    - "no_tlsv1"
    - "no_tlsv1_1"
    - "cipher_server_preference"
    - "no_compression"
  'DH_FILE': "/etc/ssl/dh2048.pem"
c2s_ciphers: 'TLS_CIPHERS'
s2s_ciphers: 'TLS_CIPHERS'
c2s_protocol_options: 'TLS_OPTIONS'
s2s_protocol_options: 'TLS_OPTIONS'
c2s_dhfile: 'DH_FILE'
s2s_dhfile: 'DH_FILE'
listen:
  -
    port: 5222
    ip: "::"
    module: ejabberd_c2s
    max_stanza_size: 262144
    shaper: c2s_shaper
    access: c2s
    starttls_required: true
    protocol_options: 'TLS_OPTIONS'
disable_sasl_mechanisms:
  - "digest-md5"
  - "X-OAUTH2"
```

### Creación de registros DNS

```bash
samba-tool dns add localhost example.tld jb A '192.168.0.3' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost 0.168.192.in-addr.arpa 3 PTR 'jb.example.tld.' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld conference CNAME 'jb.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld echo CNAME 'jb.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld pubsub CNAME 'jb.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _xmpp-client._tcp SRV 'jb.example.tld 5222 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _xmpp-server._tcp SRV 'jb.example.tld 5269 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _xmpp-server._tcp.conference.example.tld SRV 'jb.example.tld 5269 5 0' -U 'administrator'%'P@s$w0rd.123'
```

### Comprobaciones

```bash
host -t SRV _xmpp-server._tcp.example.tld
host -t SRV _xmpp-client._tcp.example.tld
host -t A jb.example.tld
dig -t SRV @example.tld _xmpp-client._tcp.example.tld
dig -t SRV @example.tld _xmpp-server._tcp.example.tld
dig -t SRV @example.tld _xmpp-server._tcp.conference.example.tld
```

### Integración con Samba AD DC

Crear nueva Cuenta de Usuario para el servicio `ejabberd`.

```bash
samba-tool user create 'ejabberd' 'P@s$w0rd.012' \
    --surname='XMPP Service' \
    --given-name='eJabberd' \
    --company='EXAMPLE' \
    --description='eJabberd XMPP Service Account'
samba-tool user setexpiry ejabberd --noexpiry
```

Crear Grupo de Usuarios de mensajería instantánea.

```bash
samba-tool group add XMPP --groupou='OU=ACME' --description='XMPP Users Group'
```

Añadir usuarios al grupo `XMPP`.

```bash
samba-tool group addmembers 'XMPP' john.doe,sheldon,leonard,rajesh
```

### Configuración del servicio.

Definir cuenta de usuario con acceso administrativo al servicio.

```bash
nano /etc/ejabberd/ejabberd.yml
```
```yml
acl:
  admin:
    user:
      - "john.doe@example.tld"
```

Definir método de autenticación.

```yml
auth_password_format: scram
fqdn: "jb.example.tld"
auth_method: ldap
ldap_servers:
  - "dc.example.tld"
ldap_encrypt: none
ldap_port: 389
ldap_rootdn: "ejabberd@example.tld"
ldap_password: "P@s$w0rd.012"
ldap_base: "OU=ACME,DC=example,DC=tld"
ldap_uids: {"sAMAccountName": "%u"}
ldap_filter: "(&(memberOf=CN=XMPP,OU=ACME,DC=example,DC=tld)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

### Compartir el roster de los usuarios

Editar el fichero `/etc/ejabberd/ejabberd.yml` y añadir en la sección `MODULES`, debajo de la opción `mod_roster: {}`, el siguiente contenido:

```yml
mod_shared_roster_ldap:
  ldap_base: "OU=ACME,DC=example,DC=tld"
  ldap_groupattr: "department"
  ldap_groupdesc: "department"
  ldap_memberattr: "sAMAccountName"
  ldap_useruid: "sAMAccountName"
  ldap_userdesc: "displayName"
  ldap_rfilter: "(objectClass=user)"
  ldap_filter: "(&(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

### Personalizar vCard de los usuarios

Editar el fichero `/etc/ejabberd/ejabberd.yml` y añadir en la sección `MODULES`, el siguiente contenido:

Para Debian 9 Stretch.

```yml
mod_vcard_ldap:
  ldap_base: "OU=ACME,DC=example,DC=tld"
  ldap_uids: {"sAMAccountName": "%u"}
  matches: infinity
  ldap_vcard_map:
    "NICKNAME": {"%s": ["givenName"]}
    "FN": {"%s": ["displayName"]}
    "EMAIL": {"%s": ["mail"]}
    "GIVEN": {"%s": ["givenName"]}
    "MIDDLE": {"%s": ["middleName"]}
    "FAMILY": {"%s": ["sn"]}
    "ORGNAME": {"%s": ["company"]}
    "ORGUNIT": {"%s": ["department"]}
    "TITLE": {"%s": ["title"]}
    "TEL": {"%s": ["telephoneNumber"]}
    "PHOTO": {"%s": ["jpegPhoto"]}
  ldap_search_fields:
    "User": "%u"
    "Full Name":  "displayName"
    "Email": "mail"
  ldap_search_reported:
    "Full Name": "FN"
    "Nickname": "NICKNAME"
    "Email": "EMAIL"
```

Para Debian 10 Buster.

```yml
mod_vcard:
  db_type: ldap
  ldap_base: "OU=ACME,DC=example,DC=tld"
  ldap_uids: {"sAMAccountName": "%u"}
  matches: infinity
  ldap_vcard_map:
    "NICKNAME": {"%s": ["givenName"]}
    "FN": {"%s": ["displayName"]}
    "EMAIL": {"%s": ["mail"]}
    "GIVEN": {"%s": ["givenName"]}
    "MIDDLE": {"%s": ["middleName"]}
    "FAMILY": {"%s": ["sn"]}
    "ORGNAME": {"%s": ["company"]}
    "ORGUNIT": {"%s": ["department"]}
    "TITLE": {"%s": ["title"]}
    "TEL": {"%s": ["telephoneNumber"]}
    "PHOTO": {"%s": ["jpegPhoto"]}
  ldap_search_fields:
    "User": "%u"
    "Full Name":  "displayName"
    "Email": "mail"
  ldap_search_reported:
    "Full Name": "FN"
    "Nickname": "NICKNAME"
    "Email": "EMAIL"
```

Reiniciar el servicio y comprobar su correcto funcionamiento.

```bash
systemctl restart ejabberd
systemctl status ejabberd
```

### Comprobaciones

Acceder a la web admnistrativa `https://jb.example.tld:5280/admin`, que provee eJabberd desde un navegador, loguearse con un usuario administrador y revisar los parámetros de configuración establecidos.

Vale destacar que una vez intregado el servicio al AD DC, no es necesario realizar cambio alguno a los usuarios, por esta vía; pues son gestionados en el mismo AD DC.

Iniciar sesión desde cualquier cliente jabber (Spark, Gajim, Pidgin) que soporte el protocolo XMPP y en la consola del servidor ejecutar:

```bash
tail -fn100 /var/log/ejabberd/ejabberd.log
```

## Instalación y configuración de Postfix/Dovecot Mail Server e integración con Samba AD DC.

### Instalación de paquetes necesarios

```bash
export DEBIAN_FRONTEND=noninteractive
apt install postfix-pcre postfix-ldap postfix-policyd-spf-python dovecot-core dovecot-ldap dovecot-pop3d dovecot-imapd dovecot-lmtpd ldap-utils mailutils
unset DEBIAN_FRONTEND
```

### Configuración del sistema

Crear grupo y usuario locales para el almacén de buzones `vmail`.

```bash
groupadd -g 5000 vmail
useradd -m -g 5000 -u 5000 -d /var/vmail -s /usr/sbin/nologin -c "Virtual Mailbox Storage" vmail
```

Crear certificado de seguridad TLS/SSL.

Para Debian 9 Stretch.

```bash
openssl req -x509 -nodes -days 3650 -sha512 \
    -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=mail.example.tld/emailAddress=postmaster@example.tld/" \
    -reqexts SAN -extensions SAN \-config <(cat /etc/ssl/openssl.cnf \
        <(printf "\n[SAN]\nsubjectAltName=DNS:smtp.example.tld,\
        DNS:pop3.example.tld,DNS:imap.example.tld,\
        DNS:webmail.example.tld,IP:192.168.0.4")) \
    -newkey rsa:4096 \
    -out /etc/ssl/certs/exampleMail.crt \
    -keyout /etc/ssl/private/exampleMail.key
```

Para Debian 10 Buster.

```bash
openssl req -x509 -nodes -days 3650 -sha512 \
    -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=mail.example.tld/emailAddress=postmaster@example.tld/" \
    -addext "subjectAltName = DNS:smtp.example.tld,\
        DNS:pop3.example.tld,DNS:imap.example.tld,\
        DNS:webmail.example.tld,IP:192.168.0.4" \
    -newkey rsa:4096 \
    -out /etc/ssl/certs/exampleMail.crt \
    -keyout /etc/ssl/private/exampleMail.key
```

```bash
openssl dhparam -out /etc/ssl/dh2048.pem 2048
chmod 0444 /etc/ssl/certs/exampleMail.crt
chmod 0400 /etc/ssl/private/exampleMail.key
```

Comprobar correcta creación del certificado.

```bash
openssl x509 -in /etc/ssl/certs/exampleMail.crt -text -noout
```

### Integración con Samba AD DC

Crear nueva Cuenta de Usuario del Dominio para el servicio `postfix`.

```bash
samba-tool user create 'postfix' 'P@s$w0rd.345' \
    --surname='Dovecot Roundcube' \
    --given-name='Postfix' \
    --company='EXAMPLE' \
    --description='Mail Service Account'
samba-tool user setexpiry postfix --noexpiry
```

Crear buzón de correo electrónico para almacén de mensajes.

```bash
samba-tool user create 'archive' 'P@s$w0rd.678' \
    --userou='OU=ACME' \
    --surname='Mail Storage' \
    --given-name='Archive' \
    --company='ACME' \
    --description='Archive Mail Storage Account' \
    --mail='archive@example.tld'
samba-tool user setexpiry archive --noexpiry
```

Crear registros DNS.

```bash
samba-tool dns add localhost example.tld mail A '192.168.0.4' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost 0.168.192.in-addr.arpa 4 PTR 'mail.example.tld.' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld @ MX 'mail.example.tld 10' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld @ TXT '"v=spf1 a:example.tld mx -all"' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld mail._domainkey TXT '"v=DKIM1; h=sha256; k=rsa;" "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOXRUYAblt65ls/zAipF1CoOhe1+9So+n6LJ3GOJzU3xDT1/V+uf9snRAEmZletTOftARX7KMBYPBCVfFt1RBvSLYbvaKVQONgFR5mW60VTYvEhrChLtkUzWGSQsZswWxzOZYyxNR1spR2eF9RSnBTCgX763in+b0uIxhlbqiNCxC9C0JN9zL+DchJl2X0v6+p9xNb2Vmc5DU7" "87SujgNEZKVG5k4d7qDgy2mdIjg/q9BVOrBLRtMxtTIB7SymTo8SSTw31mWsl8uksgYqWSm1Fu61emPgafwCAya5ftqLpeAdPGgsoNLh242LWt5pXfbFKe8I/6HDAWCiHN7dnyewIDAQAB"' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld smtp CNAME 'mail.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld pop3 CNAME 'mail.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld imap CNAME 'mail.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld autodiscover CNAME 'mail.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld autoconfig CNAME 'mail.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld webmail CNAME 'mail.example.tld' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _smtp._tcp SRV 'smtp.example.tld 25 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _smtps._tcp SRV 'smtp.example.tld 465 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _imaps._tcp SRV 'imap.example.tld 993 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _pop3s._tcp SRV 'pop3.example.tld 995 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _submission._tcp SRV 'smtp.example.tld 587 5 0' -U 'administrator'%'P@s$w0rd.123'
samba-tool dns add localhost example.tld _autodiscover._tcp SRV 'mail.example.tld 443 0 1' -U 'administrator'%'P@s$w0rd.123'
```

Crear nueva Unidad Organizativa `Email` para grupos de correo electrónico, perteneciente a `ACME`.

```bash
samba-tool ou create 'OU=Email,OU=ACME,DC=example,DC=tld' --description='Email Groups Organizational Unit'
```

Crear Grupos de Usuarios de correo electrónico.

```bash
samba-tool group add Everyone --groupou='OU=Email,OU=ACME' --description='All Users Email Group' --mail='everyone@example.tld'
```

```bash
samba-tool group add Management --groupou='OU=Email,OU=ACME' --description='Management Email Group' --mail='management@example.tld'
```

```bash
samba-tool group add Support --groupou='OU=Email,OU=ACME' --description='Technical Support Email Group' --mail='support@example.tld'
```

Añadir usuarios a los grupos creados.

```bash
samba-tool group addmembers 'Everyone' sheldon,leonard,rajesh
samba-tool group addmembers 'Management' sheldon
samba-tool group addmembers 'Support' rajesh,sheldon
```

### Configuración de Postfix

Realizar copia de seguridad de los ficheros de configuración.

```bash
cp /etc/postfix/main.cf{,.org}
cp /etc/postfix/master.cf{,.org}
```

Declarar dominio de correo a gestionar.

```bash
postconf -e "mydomain = example.tld"
postconf -e "smtpd_sasl_local_domain = example.tld"
postconf -e "virtual_mailbox_domains = example.tld"
```

Definir transporte virtual del dominio de correo.

```bash
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
```

Definir usuarios virtuales de correo electrónico.

```bash
postconf -e "smtpd_sender_login_maps = proxy:ldap:/etc/postfix/virtual_sender_login_maps.cf"
```

```bash
nano /etc/postfix/virtual_sender_login_maps.cf

server_host = dc.example.tld
server_port = 389
version = 3
bind = yes
start_tls = no
bind_dn = postfix@example.tld
bind_pw = P@s$w0rd.345
search_base = OU=ACME,DC=example,DC=tld
scope = sub
query_filter = (&(objectClass=person)(userPrincipalName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
result_attribute = userPrincipalName
debuglevel = 0
```

Definir buzón almacén de correo electrónico.

```bash
postconf -e "always_bcc = archive@example.tld"
```

Definir buzones virtuales de correo electrónico.

```bash
postconf -e "virtual_minimum_uid = 5000"
postconf -e "virtual_uid_maps = static:5000"
postconf -e "virtual_gid_maps = static:5000"
postconf -e "virtual_mailbox_base = /var/vmail"
postconf -e "virtual_mailbox_maps = proxy:ldap:/etc/postfix/virtual_mailbox_maps.cf"
```

```bash
nano /etc/postfix/virtual_mailbox_maps.cf

server_host = dc.example.tld
server_port = 389
version = 3
bind = yes
start_tls = no
bind_dn = postfix@example.tld
bind_pw = P@s$w0rd.345
search_base = OU=ACME,DC=example,DC=tld
scope = sub
query_filter = (&(objectClass=person)(userPrincipalName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
result_attribute = userPrincipalName
result_format = %d/%u/Maildir/
debuglevel = 0
```

Definir listas, aliases y forwardings virtuales de correo electrónico.

```bash
postconf -e "virtual_alias_maps = proxy:ldap:/etc/postfix/virtual_list_maps.cf, proxy:ldap:/etc/postfix/virtual_alias_maps.cf, proxy:ldap:/etc/postfix/virtual_forwarding_maps.cf"
```

```bash
nano /etc/postfix/virtual_list_maps.cf

server_host = dc.example.tld
server_port = 389
version = 3
bind = yes
start_tls = no
bind_dn = postfix@example.tld
bind_pw = P@s$w0rd.345
search_base = OU=ACME,DC=example,DC=tld
scope = sub
query_filter = (&(objectClass=person)(memberOf=cn=%u,OU=Email,OU=ACME,DC=example,DC=tld)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
result_attribute = userPrincipalName
debuglevel = 0
```

```bash
nano /etc/postfix/virtual_alias_maps.cf

server_host = dc.example.tld
server_port = 389
version = 3
bind = yes
start_tls = no
bind_dn = postfix@example.tld
bind_pw = P@s$w0rd.345
search_base = OU=ACME,DC=example,DC=tld
scope = sub
query_filter = (&(objectClass=person)(otherMailbox=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
result_attribute = userPrincipalName
debuglevel = 0
```

```bash
nano /etc/postfix/virtual_forwarding_maps.cf

server_host = dc.example.tld
server_port = 389
version = 3
bind = yes
start_tls = no
bind_dn = postfix@example.tld
bind_pw = P@s$w0rd.345
search_base = OU=ACME,DC=example,DC=tld
scope = sub
query_filter = (&(objectClass=person)(mail=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
result_attribute = mail, pager
debuglevel = 0
```

> **NOTA**: Los atributos `otherMailbox` y `pager` pueden editarse utilizando el comando `samba-tool user edit <username>` o mediante las herramientas administrativas GUI `RSAT` o `Apache Directory Studio`.

Habilitar puerto seguro `TCP\587 Submission` y establecer comunicación con `dovecot`.

```bash
nano /etc/postfix/master.cf

submission inet n - y - 10 smtpd
    -o syslog_name=postfix/submission
    -o smtpd_tls_security_level=encrypt
    -o smtpd_sasl_auth_enable=yes
    -o smtpd_tls_cert_file=/etc/ssl/certs/exampleMail.crt
    -o smtpd_tls_key_file=/etc/ssl/private/exampleMail.key
    -o smtpd_client_restrictions=permit_sasl_authenticated,reject
dovecot unix - n n - - pipe
    flags=DRhu user=vmail:vmail argv=/usr/lib/dovecot/dovecot-lda -f ${sender} -d ${recipient}
```

#### Comprobaciones

```bash
postmap -q leonard@example.tld ldap:/etc/postfix/virtual_sender_login_maps.cf
postmap -q rajesh@example.tld ldap:/etc/postfix/virtual_mailbox_maps.cf
postmap -q everyone@example.tld ldap:/etc/postfix/virtual_list_maps.cf
postmap -q postmaster@example.tld ldap:/etc/postfix/virtual_alias_maps.cf
postmap -q sheldon@example.tld ldap:/etc/postfix/virtual_forwarding_maps.cf
```

Reiniciar el servicio.

```bash
systemctl restart postfix.service
```

### Configuración del servicio Dovecot

* Realizar salva de seguridad del fichero de configuración principal.

```bash
cp /etc/dovecot/dovecot.conf{,.org}
```

* Crear script de alerta de sobreuso de cuota y asignar permiso
  de ejecución.

```bash
nano /usr/local/bin/quota-warning

#!/bin/bash

PERCENT=${1}
USER=${2}
DOMAIN=${USER#*@}

cat << EOT | /usr/lib/dovecot/dovecot-lda -d ${USER} -o "plugin/quota=maildir:User quota:noenforcing"
From: no-reply@${DOMAIN}
Subject: ALERTA: USO DE CUOTA SUPERIOR AL ${PERCENT}%

ESTIMADO(A) USUARIO(A),

SU BUZON DE CORREO ACTUALMENTE OCUPA MAS DEL ${PERCENT}% DE LA CUOTA
ASIGNADA. BORRE ALGUNOS CORREOS VIEJOS PARA PODER SEGUIR RECIBIENDO
EMAILS.

MENSAJE AUTOMATIZADO DEL SISTEMA
EOT

exit 0
```

```bash
chmod +x /usr/local/bin/quota-warning
```

#### Integración con Samba AD DC

```bash
nano /etc/dovecot/dovecot.conf

userdb {
    args = /etc/dovecot/dovecot-ldap.conf
    driver = ldap
}
passdb {
    args = /etc/dovecot/dovecot-ldap.conf
    driver = ldap
}
```

```bash
nano /etc/dovecot/dovecot-ldap.conf

hosts = dc.example.tld:389
auth_bind = yes
ldap_version = 3
dn = postfix@example.tld
dnpass = P@s$w0rd.345
base = OU=ACME,DC=example,DC=tld
deref = never
scope = subtree
user_filter = (&(objectClass=person)(userPrincipalName=%u)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
user_attrs = maxStorage=quota_rule=*:bytes=%$
pass_filter = (&(objectClass=person)(userPrincipalName=%u)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
pass_attrs = userPassword=password
default_pass_scheme = CRYPT
```

> **NOTA**: El atributo `maxStorage` puede editarse utilizando el comando `samba-tool user edit <username>` o mediante las herramientas administrativas GUI `RSAT` o `Apache Directory Studio`.

Reiniciar el servicio.

```bash
systemctl restart dovecot.service
```

### Configuración del servicio Webmail

#### Roundcubemail

Descargar la última versión completa estable, disponible en el sitio [Roundcube Webmail Downloads](https://roundcube.net/download/); descomprimir el paquete en el sistema y asignar permisos.

```bash
tar -xzmf roundcubemail-*-complete.tar.gz -C /opt/
mv /opt/roundcubemail-* /opt/roundcube
ln -s /opt/roundcube/bin/{cleandb,gc}.sh /etc/cron.daily/
chown -R root:www-data /opt/roundcube/
find /opt/roundcube/ -type d \-exec chmod 0755 {} \;
find /opt/roundcube/ -type f \-exec chmod 0644 {} \;
chmod 0770 /opt/roundcube/{logs,temp}
```

> Actualización
>
>```bash
>tar -xzf roundcubemail-*-complete.tar.gz
>cd roundcubemail-*/
>./bin/install.sh /opt/roundcube/
>```

#### PostgreSQL

Instalar gestor de base de datos `PostgreSQL`.

```bash
apt install postgresql
```

Crear base de datos para `roundcubemail`.

```bash
su - postgres
psql
\password postgres
CREATE DATABASE roundcubemail WITH TEMPLATE template0 ENCODING 'UNICODE';
\q
```

Inicializar la base de datos.

```bash
psql -h localhost -U postgres -W -f /opt/roundcube/SQL/postgres.initial.sql roundcubemail
```

#### Nginx

Instalar servidor web `Nginx`.

```bash
apt install nginx-full php-fpm php-pear php-mbstring php-intl php-ldap php-gd php-imagick php-pgsql php-curl php-json php-xml php-bz2 php-zip
```

Definir zona horaria.

```bash
sed -i "s/^;date\.timezone =.*$/date\.timezone = 'America\/Havana'/;
        s/^;cgi\.fix_pathinfo=.*$/cgi\.fix_pathinfo = 0/" \
        /etc/php/7*/fpm/php.ini
```

Crear fichero de publicación web.

```bash
nano /etc/nginx/sites-available/roundcube

proxy_cache_path /tmp/cache keys_zone=cache:10m levels=1:2 inactive=600s max_size=100m;
server {
    listen 80;
    listen 443 ssl http2;
    root /opt/roundcube;
    server_name webmail.example.tld;
    if ($scheme = http) {
        return 301 https://$server_name$request_uri;
    }
    ssl_certificate /etc/ssl/certs/exampleMail.crt;
    ssl_certificate_key /etc/ssl/private/exampleMail.key;
    ssl_dhparam /etc/ssl/dh2048.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling_verify on;
    ssi on;
    resolver 127.0.0.1 valid=300s;
    resolver_timeout 5s;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Content-Type-Options nosniff;
    proxy_cache cache;
    proxy_cache_valid 200 1s;
    location ~ [^/]\.php(/|$) {
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        if (!-f $document_root$fastcgi_script_name) {
            return 404;
        }
        fastcgi_param HTTP_PROXY "";
        fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
        include snippets/fastcgi-php.conf;
    }
    rewrite ^(/(?:a|A)utodiscover/(?:a|A)utodiscover\.xml)$ /autodiscover/autodiscover.xml;
    rewrite ^(/mail/config-v1.1\.xml|/.well-known/autoconfig/mail/config-v1.1\.xml|/autoconfig/mail/config-v1.1\.xml)$ /autoconfig/mail/config-v1.1.xml;
    location ~ /\. {
        deny all;
    }
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    location = /robots.txt {
        access_log off;
        log_not_found off;
    }
    location / {
        index index.php;
        location ~ ^/favicon.ico$ {
            root /opt/roundcube/skins/larry/images;
            log_not_found off;
            access_log off;
            expires max;
        }
        location ~ ^/(bin|SQL|config|temp|logs)/ {
             deny all;
        }
        location ~ ^/(README|INSTALL|LICENSE|CHANGELOG|UPGRADING)$ {
            deny all;
        }
        location ~ ^/(.+\.md)$ {
            deny all;
        }
        location ~ ^/program/resources/(.+\.pdf)$ {
            deny all;
            log_not_found off;
            access_log off;
        }
        location ~ ^/\. {
            deny all;
            access_log off;
            log_not_found off;
        }
    }
    access_log /var/log/nginx/roundcube_access.log;
    error_log /var/log/nginx/roundcube_error.log;
}
```

Habilitar el servicio.

```bash
ln -s /etc/nginx/sites-available/roundcube /etc/nginx/sites-enabled/
```

#### Apache2

Instalar servidor web `Apache2`.

```bash
apt install apache2 libapache2-mod-php php-pear php-mbstring php-intl php-ldap php-gd php-imagick php-pgsql php-curl php-json php-xml php-bz2 php-zip
```

Definir zona horaria.

```bash
sed -i "s/^;date\.timezone =.*$/date\.timezone = 'America\/Havana'/;
        s/^;cgi\.fix_pathinfo=.*$/cgi\.fix_pathinfo = 0/" \
        /etc/php/7*/apache2/php.ini
```

Crear fichero de publicación web.

```bash
nano /etc/apache2/sites-available/roundcube.conf

<VirtualHost *:80>
    RewriteEngine on
    RewriteCond %{HTTPS} =off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [QSA,L,R=301]
    RewriteCond %{REQUEST_URI} ^/autodiscover/autodiscover.xml
    RewriteRule ^(.*)$ https://%{HTTP_HOST}/autodiscover/autodiscover.xml [R=301,L]
    RewriteCond %{REQUEST_URI} ^/.well-known/autoconfig/mail/config-v1.1.xml
    RewriteRule ^(.*)$ https://%{HTTP_HOST}/autoconfig/mail/config-v1.1.php [R=301,L]
    RewriteCond %{REQUEST_URI} ^/autoconfig/mail/config-v1.1.xml
    RewriteRule ^(.*)$ https://%{HTTP_HOST}/autoconfig/mail/config-v1.1.php [R=301,L]
    RewriteCond %{REQUEST_URI} ^/mail/config-v1.1.xml
    RewriteRule ^(.*)$ https://%{HTTP_HOST}/autoconfig/mail/config-v1.1.php [R=301,L]
</VirtualHost>
<IfModule mod_ssl.c>
    <VirtualHost *:443>
        ServerName webmail.example.tld
        ServerAdmin webmaster@example.tld
        DocumentRoot /opt/roundcube
        DirectoryIndex index.php
        ErrorLog ${APACHE_LOG_DIR}/roundcube_error.log
        CustomLog ${APACHE_LOG_DIR}/roundcube_access.log combined
        SSLEngine on
        SSLCertificateFile /etc/ssl/certs/exampleMail.crt
        SSLCertificateKeyFile /etc/ssl/private/exampleMail.key
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
            SSLOptions +StdEnvVars
        </Directory>
        BrowserMatch "MSIE [2-6]" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0
        BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown
        <Directory /opt/roundcube>
            Options +FollowSymlinks
            AllowOverride All
            Require all granted
            SetEnv HOME /opt/roundcube
            SetEnv HTTP_HOME /opt/roundcube
            <IfModule mod_dav.c>
                Dav off
            </IfModule>
        </Directory>
        <Directory /opt/roundcube/program/resources>
            <FilesMatch "\.(pdf)$">
                Require all denied
            </FilesMatch>
        </Directory>
    </VirtualHost>
</IfModule>
```

Habilitar el servicio.

```bash
a2ensite roundcube.conf
```

#### Autodescubrimiento y autoconfiguración

```bash
mkdir -p /opt/roundcube/{autodiscover,autoconfig/mail}
```
```xml
nano /opt/roundcube/autodiscover/autodiscover.xml

<?xml version="1.0" encoding="utf-8" ?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
        <Protocol>
          <Type>IMAP</Type>
          <Server>imap.example.tld</Server>
          <Port>993</Port>
          <DomainRequired>off</DomainRequired>
          <LoginName>%EMAILADDRESS%</LoginName>
          <SPA>off</SPA>
          <SSL>on</SSL>
          <AuthRequired>on</AuthRequired>
        </Protocol>
        <Protocol>
          <Type>POP3</Type>
          <Server>pop3.example.tld</Server>
          <Port>995</Port>
          <DomainRequired>off</DomainRequired>
          <LoginName>%EMAILADDRESS%</LoginName>
          <SPA>off</SPA>
          <SSL>on</SSL>
          <AuthRequired>on</AuthRequired>
        </Protocol>
        <Protocol>
          <Type>SMTP</Type>
          <Server>smtp.example.tld</Server>
          <Port>587</Port>
          <DomainRequired>off</DomainRequired>
          <LoginName>%EMAILADDRESS%</LoginName>
          <SPA>off</SPA>
          <SSL>on</SSL>
          <Encryption>STARTTLS</Encryption>
          <AuthRequired>on</AuthRequired>
          <UsePOPAuth>off</UsePOPAuth>
          <SMTPLast>off</SMTPLast>
        </Protocol>
        <Protocol>
          <Type>SMTP</Type>
          <Server>smtp.example.tld</Server>
          <Port>465</Port>
          <DomainRequired>off</DomainRequired>
          <LoginName>%EMAILADDRESS%</LoginName>
          <SPA>off</SPA>
          <SSL>on</SSL>
          <Encryption>STARTTLS</Encryption>
          <AuthRequired>on</AuthRequired>
          <UsePOPAuth>off</UsePOPAuth>
          <SMTPLast>off</SMTPLast>
        </Protocol>
      </Account>
  </Response>
</Autodiscover>
```
```xml
nano /opt/roundcube/autoconfig/mail/config-v1.1.xml

<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
    <emailProvider id="example.tld">
        <domain>example.tld</domain>
        <displayName>Example TLD Email Server</displayName>
        <displayShortName>ExampleTLD</displayShortName>
        <incomingServer type="imap">
            <hostname>imap.example.tld</hostname>
            <port>993</port>
            <socketType>SSL</socketType>
            <authentication>password-cleartext</authentication>
            <username>%EMAILADDRESS%</username>
        </incomingServer>
      <incomingServer type="pop3">
            <hostname>pop3.example.tld</hostname>
            <port>995</port>
            <socketType>SSL</socketType>
            <authentication>password-cleartext</authentication>
            <username>%EMAILADDRESS%</username>
            <pop3>
                <leaveMessagesOnServer>true</leaveMessagesOnServer>
                <downloadOnBiff>true</downloadOnBiff>
                <daysToLeaveMessagesOnServer>10</daysToLeaveMessagesOnServer>
            </pop3>
        </incomingServer>
        <outgoingServer type="smtp">
            <hostname>smtp.example.tld</hostname>
            <port>587</port>
            <socketType>STARTTLS</socketType>
            <authentication>password-cleartext</authentication>
            <username>%EMAILADDRESS%</username>
        </outgoingServer>
        <outgoingServer type="smtp">
            <hostname>smtp.example.tld</hostname>
            <port>465</port>
            <socketType>SSL</socketType>
            <authentication>password-cleartext</authentication>
            <username>%EMAILADDRESS%</username>
        </outgoingServer>
    </emailProvider>
</clientConfig>
```

#### Integración con Samba AD DC

```bash
nano /opt/roundcube/config/config.inc.php
```
```php
// Database
$config['db_dsnw'] = 'pgsql://postgres:<contraseña-usuario-postgres>@localhost/roundcubemail';
// Samba AD DC Address Book
$config['autocomplete_addressbooks'] = array(
    'sql',
    'global_ldap_abook'
);
$config['ldap_public']["global_ldap_abook"] = array(
    'name'              => 'Mailboxes',
    'hosts'             => array('dc.example.tld'),
    'port'              => 389,
    'use_tls'           => false,
    'ldap_version'      => '3',
    'network_timeout'   => 10,
    'user_specific'     => false,
    'base_dn'           => 'OU=ACME,DC=example,DC=tld',
    'bind_dn'           => 'postfix@example.tld',
    'bind_pass'         => 'P@s$w0rd.345',
    'writable'          => false,
    'search_fields' => array(
        'mail',
        'cn',
        'sAMAccountName',
        'displayName',
        'sn',
        'givenName',
    ),
    'fieldmap' => array(
        'name'          => 'cn',
        'surname'       => 'sn',
        'firstname'     => 'givenName',
        'title'         => 'title',
        'email'         => 'mail:*',
        'phone:work'    => 'telephoneNumber',
        'phone:mobile'  => 'mobile',
        'phone:workfax' => 'facsimileTelephoneNumber',
        'street'        => 'street',
        'zipcode'       => 'postalCode',
        'locality'      => 'l',
        'department'    => 'department',
        'notes'         => 'description',
        'photo'         => 'jpegPhoto',
    ),
    'sort'          => 'cn',
    'scope'         => 'sub',
    'filter'        => '(&(|(objectclass=person))(!(mail=archive@example.tld))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    'fuzzy_search'  => true,
    'vlv'           => false,
    'sizelimit'     => '0',
    'timelimit'     => '0',
    'referrals'     => false,
    'group_filters' => array(
        'departments' => array(
            'name'    => 'Lists',
            'scope'   => 'sub',
            'base_dn' => 'OU=Email,OU=ACME,DC=example,DC=tld',
            'filter'  => '(objectClass=group)',
        ),
    ),
);
```

## Comandos y herramientas útiles

* `samba-tool` (herramienta principal para administración `samba`)
* `testparam|samba-tool testparm` (chequeo errores de configuración `samba`)
* `wbinfo` (consultar información utilizando `windbind`)
* `pdbedit` (manipular base datos de usuarios `samba`)
* `ldapsearch` (consultar servicios de directorios `LDAP`)
* `dhcpd -t` (chequeo errores de configuración `isc-dhcp-server`)
* `RSAT` (herramientas administración servidor remoto `windows`)
* `Apache Directory Studio` (herramienta administración servicios de directorio `LDAP`)
* `named-checkconf` (chequeo errores de configuración `bind9`)
* `squid -kc` (chequeo errores de sintáxis configuración `squid`)
* `postconf` (herramienta principal de configuración `postfix`)
* `postfix check` (chequeo errores de configuración `postfix`)
* `doveconf -n` (muestra los parámetros configurados)
* `nginx -t` (chequeo errores de configuración `nginx`)
* `apache2ctl configtest` (chequeo errores de configuración `apache2`)

## Consideraciones finales

Todas las configuraciones expuestas en esta guía han sido probadas satisfactoriamente -si los pasos descritos se siguen a cabalidad-, en contenedores (CT) y máquinas virtuales (VM), gestionadas con Proxmox v5/v6.

Los CTs que ejecuten servicios que utilicen autenticación `Kerberos`, deben crearse con las características `fuse`, `nesting` y la opción `Unprivileged mode` desmarcada.

En CTs para que el servidor Samba AD DC funcione correctamente; además de lo descrito en el párrafo anterior, debe activarse la característica `cifs`.

Para un correcto funcionamiento del servidor `NTP` en CTs se debe eliminar la restricción de acceso al reloj del sistema, editando el fichero de configuración del contendor y agregando las líneas `lxc.cap.drop:` y `lxc.cap.drop: mac_admin mac_override sys_module sys_rawio`, al final. Ejemplo:

```bash
nano /etc/pve/lxc/101.conf

arch: amd64
cores: 1
features: fuse=1,nesting=1
hostname: dc
memory: 768
nameserver: 127.0.0.1
net0: name=eth0,bridge=vmbr0,gw=192.168.0.254,hwaddr=00:00:00:00:00:00,ip=192.168.0.1/24,type=veth
ostype: debian
rootfs: local-lvm:vm-101-disk-0,size=10G
searchdomain: example.tld
swap: 1024
lxc.cap.drop:
lxc.cap.drop: mac_admin mac_override sys_module sys_rawio
```

La integración de los servicios descritos en esta guía, también son funcionales con el servicio de directorio `Active Directory` de Microsoft Windows.

## Referencias

### Samba AD DC+Bind9 DNS Server+NTP+DHCP

* [Setting up Samba as an Active Directory Domain Controller](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller)
* [Samba changelog: strong auth required](https://wiki.samba.org/index.php/Samba_4.4_Features_added/changed#ldap_server_require_strong_auth_.28G.29)
* [Configure DHCP to update DNS records with BIND9](https://wiki.samba.org/index.php/Configure_DHCP_to_update_DNS_records_with_BIND9)
* [Setting up a BIND DNS Server](https://wiki.samba.org/index.php/Setting_up_a_BIND_DNS_Server)
* [Password Settings Objects](https://wiki.samba.org/index.php/Password_Settings_Objects)
* [PDC sencillo con Samba 4 Debian 9](https://admlinux.cubava.cu/2018/02/21/pdc-sencillo-con-samba-4-en-debian-9/)
* [Active Directory Domain Controller con Samba4 + Bind9 y Delegación de zona Actualizado](http://admlinux.cubava.cu/2019/01/14/addc-con-samba4-bind9-y-delegacion-de-zona/)
* [PDC + Samba 4 + DLZ o PDC con Samba4 y delegación de zona Debian9](http://admlinux.cubava.cu/2018/02/27/pdc-con-samba-4-dlz-en-debian-9/)
* [Unir un servidor Debian 8 y sus derivados en Dominio Active Directory Samba4 ó Windows Server](http://cubatic.cubava.cu/2018/10/29/unir-un-servidor-debian-8-y-sus-derivados-en-dominio-active-directory-samba4-o-windows-server/)
* [Samba4 as Active Directory Domain Controller](https://redtic.uclv.cu/dokuwiki/samba4_as_ad_dc)
* [SAMBA - Debian - Installation d'un AD Samba pour un nouveau domaine](https://dev.tranquil.it/wiki/SAMBA_-_Debian_-_Installation_d%27un_AD_Samba_pour_un_nouveau_domaine)
* [SAMBA - Integration avec bind9](https://dev.tranquil.it/wiki/SAMBA_-_Integration_avec_bind9)
* [SAMBA - Configuration Samba4 NTP](https://dev.tranquil.it/wiki/SAMBA_-_Configuration_Samba4_NTP)
* [Time Synchronisation - SambaWiki - Samba.org](https://wiki.samba.org/index.php/Time_Synchronisation)
* [SERNET: Una solución para la instalación de un controlador de dominio en Samba4 Parte I](http://cubatic.cubava.cu/2018/08/01/sernet-una-solucion-para-la-instalacion-de-un-controlador-de-dominio-en-samba4-parte-i/)
* [SERNET: Una solución para la instalación de un controlador de dominio en Samba4 Parte II](http://cubatic.cubava.cu/2018/08/01/sernet-una-solucion-para-la-instalacion-de-un-controlador-de-dominio-en-samba4-parte-i-esta-bloqueado-sernet-una-solucion-para-la-instalacion-de-un-controlador-de-dominio-en-samb/)
* [Herramientas de administración de servidor remoto (RSAT) para windows](https://support.microsoft.com/es-es/help/2693643/remote-server-administration-tools-rsat-for-windows-operating-systems)
* [Samba 4 como Controlador de Dominios AD DC en Debian 9](https://usuariodebian.blogspot.com/2019/04/samba-4-como-controlador-de-dominios-ad.html)
* [Setting up a Samba 4 Domain Controller on Debian 9](https://jonathonreinhart.com/posts/blog/2019/02/11/setting-up-a-samba-4-domain-controller-on-debian-9/)
* [Raising the Functional Levels](https://wiki.samba.org/index.php/Raising_the_Functional_Levels)
* [Samba/Active Directory domain controller - ArchWiki](https://wiki.archlinux.org/index.php/Samba/Active_Directory_domain_controller)
* [ISC DHCP Server - Debian Wiki](https://wiki.debian.org/DHCP_Server)
* [How to Configure Group Policy Central Store](https://activedirectorypro.com/configure-group-policy-central-store/)
* [ Active Directory - Creating a Group Policy Central Store](https://www.petri.com/creating-group-policy-central-store)
* [GPO Backup and Restore](https://wiki.samba.org/index.php/GPO_Backup_and_Restore)
* [Create an Active Directory Infrastructure with Samba4 on Ubuntu – Part 1](https://www.tecmint.com/install-samba4-active-directory-ubuntu/)
* [Manage Samba4 Active Directory Infrastructure from Windows10 via RSAT – Part 3](https://www.tecmint.com/manage-samba4-ad-from-windows-via-rsat/)
* [Critical Security Flaws in Samba Released on April 12, 2016 ](https://access.redhat.com/articles/2243351)
* [Group Policy Home](https://getadmx.com/)
* [Mapping Active Directory Domain Services attributes to properties in System Center - Service Manager](https://docs.microsoft.com/en-us/system-center/scsm/ad-ds-attribs?view=sc-sm-2019)
* [The Chromium Projects - Policy Templates](https://www.chromium.org/administrators/policy-templates)
* [chrony.conf(5) Manual Page](https://chrony.tuxfamily.org/doc/2.4/chrony.conf.html)
* [Configure NTP Client : Debian](https://www.server-world.info/en/note?os=Debian_10&p=ntp&f=3)

### Squid Proxy Server

* [Squid Cache Wiki Configuring a Squid Server to authenticate off Active Directory](https://wiki.squid-cache.org/ConfigExamples/Authenticate/WindowsActiveDirectory)
* [Configurer un proxy Squid avec Kerberos et Samba](https://dev.tranquil.it/wiki/SAMBA_-_Configurer_un_proxy_Squid_avec_Kerberos_et_Samba)
* [Getting squid proxy to authenticate with AD or LDAP](https://serverfault.com/questions/939550/getting-squid-proxy-to-authenticate-with-ad-or-ldap)
* [Squid Installation with AD authentication - It Portal](https://itportal.org/squid-installation-with-ad-authentication/)
* [Step 5. Configure Kerberos authentication on Squid](https://docs.diladele.com/administrator_guide_6_4/active_directory/kerberos/index.html)
* [linux - Authenticating Squid 3.5 with Active Directory](https://unix.stackexchange.com/questions/491261/authenticating-squid-3-5-with-active-directory-samba-4-on-ubuntu-16-04)
* [Squid + Samba4, parte 1](https://admlinux.cubava.cu/2019/02/14/squid-samba4-parte-1/)
* [Squid+Samba4, parte 1](https://www.sysadminsdecuba.com/2019/02/squid-samba4-parte-1/)
* [Creating a Kerberos service principal name and keytab file](https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.multiplatform.doc/ae/tsec_kerb_create_spn.html)
* [Configurar Servidor Proxy-Http Squid3.X con autenticación por protocolo Kerberos](https://cubatic.cubava.cu/2018/11/13/configurar-servidor-proxy-http-squid3-x-con-autenticacion-por-protocolo-kerberos/)
* [wsauth Diladele](http://packages.diladele.com/websafety/7.0.0.7A5E/amd64/release/debian9/websafety-7.0.0.7A5E_amd64.deb)

### eJabberd XMPP Server

* [Installing ejabberd](https://docs.ejabberd.im/admin/installation/)
* [How to install Ejabberd XMPP Server on Ubuntu 18.04 / Ubuntu 16.04](https://computingforgeeks.com/how-to-install-ejabberd-xmpp-server-on-ubuntu-18-04-ubuntu-16-04/)
* [installation - ejabberd (18.01-2) install on ubuntu server 18](https://serverfault.com/questions/929523/ejabberd-18-01-2-install-on-ubuntu-server-18-fails-cannot-start-ejabberd)
* [Configure a simple chat server using ejabberd ( on Debian)](https://www.geekonline.in/blog/2018/10/28/configure-a-simple-chat-server-using-ejabberd-on-debian/)
* [Configure ldap authentication (active directory)](https://www.ejabberd.im/node/2962/index.html)
* [Ejabberd Active Directory LDAP Login](https://raymii.org/s/tutorials/Ejabberd_Active_Directory_LDAP_Login.html)
* [Making ejabberd 14.12 work with Microsoft Windows Active Directory](http://s.co.tt/2015/02/05/making-ejabberd-14-12-work-with-microsoft-windows-active-directory-ldap/)
* [Remote authentication of users using Active Directory](https://support.freshservice.com/support/solutions/articles/169196-setting-up-active-directory-single-sign-on-sso-for-remote-authentication)
* [Ejabberd + Samba4 + Shared Roster](https://admlinux.cubava.cu/2019/03/04/ejabberd-samba4-shared-roster/)
* [Install ejabberd with Active Directory SSO backend](https://twistedlinux.wordpress.com/2016/02/11/install-ejabberd-with-active-directory-sso-backend/)
* [Authenticate Against SASL GSSAPI](https://www.ejabberd.im/cyrsasl_gssapi/index.html)
* [Ejabberd with GSSAPI support](https://launchpad.net/~metlov/+archive/ubuntu/ejabberd-gssapi)

### Postfix/Dovecot/Roundcube Mail Server

* [Samba4 + Postfix/Dovecot/SASL](http://admlinux.cubava.cu/2018/06/27/samba4-postfix-dovecot-sasl/)
* [Provide subjectAltName to OpenSSL directly on the command line](https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line)
* [Know about SAN Certificate and How to Create With OpenSSL](https://geekflare.com/san-ssl-certificate/)
* [Integrate Microsoft Active Directory for user authentication and address book](https://docs.iredmail.org/active.directory.html)
* [How to Integrate iRedMail Roundcube with Samba4 AD DC - Part 12](https://www.tecmint.com/integrate-iredmail-roundcube-with-samba4-ad-dc/)
* [Postfix/Dovecot Authentication Against Active Directory On CentOS 5.x](https://www.howtoforge.com/postfix-dovecot-authentication-against-active-directory-on-centos-5.x)
* [get SOGo, iRedmail and Samba 4 AD DS in perfect harmony](https://drdata.blogg.se/2013/july/get-sogo-iredmail-and-samba-4-ad-ds-in-perfect-harmony.html)
* [How to Set Up an Email Server with Postfix, Dovecot and Roundcube on Ubuntu 18.04](https://www.tekfansworld.com/how-to-set-up-an-email-server-with-postfix-dovecot-and-roundcube-on-ubuntu-18-04.html)
* [How To Use Iredmail](http://hy-tek.net/absx/zvouq)
* [Cuotas al correo de Samba4 + Postfix + Dovecot + SASL](https://admlinux.cubava.cu/2019/02/15/cuotas-al-correo-de-samba4-postfix-dovecot-sasl/)
* [HowTo - Dovecot Wiki](https://wiki.dovecot.org/HowTo)
* [postfix dovecot and microsoft AD | DigitalOcean](https://www.digitalocean.com/community/questions/postfix-dovecot-and-microsoft-ad)
* [Virtual user mail system with Postfix, Dovecot and Roundcube - ArchWiki](https://wiki.archlinux.org/index.php/Virtual_user_mail_system_with_Postfix,_Dovecot_and_Roundcube)
* [Postfix with Samba AD-DC – ADHainesTech.ca](http://adhainestech.ca/postfix-with-samba-ad-dc/)
* [Shared Address Book (LDAP) - Linux Home Server HOWTO](https://www.brennan.id.au/20-Shared_Address_Book_LDAP.html)
* [Authenticating Dovecot against Active Directory](https://wiki.samba.org/index.php/Authenticating_Dovecot_against_Active_Directory)
* [Authentication/Kerberos -Dovecot Wiki](https://wiki.dovecot.org/Authentication/Kerberos)
* [Configuration: LDAP Address Books](https://github.com/roundcube/roundcubemail/wiki/Configuration:-LDAP-Address-Books)
* [Postfix Virtual Hosting With LDAP Backend And With Dovecot As IMAP/POP3 Server On Ubuntu Bionic Beaver 18.04 LTS](https://www.howtoforge.com/tutorial/postfix-virtual-hosting-with-ldap-backend-and-dovecot-imap-pop3-server-on-ubuntu-bionic-beaver-1804-lts/)
* [Virtual domain alias and LDAP](http://postfix.1071664.n5.nabble.com/Virtual-domain-alias-and-LDAP-td16216.html)
* [SorkVacationWithGnarwl](https://wiki.horde.org/SorkVacationWithGnarwl)
* [Mail forwarding with Postfix and LDAP](https://b.aklein.me/mail-forwarding-with-postfix-and-ldap)
* [Postfix and Ldap (Forward and Redirect)](https://groups.google.com/g/list.postfix.users/c/T8IfENFHzhs)
* [ luisbosque / simple_vacation ](https://github.com/luisbosque/simple_vacation)
* [Topic: active directory & forwarding messages](https://forum.iredmail.org/topic11358-iredmail-support-active-directory-forwarding-messages.html)

### Proxmox VE

* [apache2.service: Failed to set up mount namespacing: Permission denied](https://forum.proxmox.com/threads/apache2-service-failed-to-set-up-mount-namespacing-permission-denied.56871/)
* [[SOLVED] Problem LXC mariadb debian 10](https://forum.proxmox.com/threads/problem-lxc-mariadb-debian-10.55926/)
* [LXC - perl: warning: Setting locale failed](https://forum.proxmox.com/threads/lxc-perl-warning-setting-locale-failed.32173/)
* [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
