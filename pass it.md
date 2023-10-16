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

