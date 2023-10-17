# MIS NOTAS CEH PRACTICAL V12

## Scanning and Enumeration (Siempre *sudo su* antes de ejecutarlo)

Escaneo para hosts activos dentro de una red, con **-A** se puede ver el hostname de la maquina: 
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
Para **desencriptar archivos** --> Cryptool (Windows, si no mencionan el Key length se presiona directamente decrypt, recuerda al buscar el archivo que este seleccionada en la ventana la opcion All Files (.*))

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
