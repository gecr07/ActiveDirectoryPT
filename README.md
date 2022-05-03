# Active Directory Pentest

Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

## fully qualified domain name for the host

<name.domain>


## Wireshark 

Intenta ver el trafico de la red


## Responder modo pasivo solo a escucha

>sudo responder -I ens224 -A 

## MDNS

Traducción del inglés-En las redes informáticas, el protocolo DNS de multidifusión resuelve los nombres de host en direcciones IP dentro de redes pequeñas que no incluyen un servidor de nombres local.

## FPing

Herramienta opcional para hacer barridos de ping ( hay otras opciones)

>ping -c 1 IP (-n en linux)

Here we'll start fping with a few flags: a to show targets that are alive, s to print stats at the end of the scan, g to generate a target list from the CIDR network, and q to not show per-target results.

>fping -asgq 172.126.5.0/23

>sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum

## User Listas generadores 

>https://github.com/insidetrust/statistically-likely-usernames


## Kerbrute 

Para checar usuarios validos se usa contra DC por ejemplo se prueba el usuario jsmith recuerda que tiene que tener el kerberos activado puerto 88.

>kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

# Poison the Network

## LLMNR & NBT-NS Primer

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.




# Hashes 

NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash.  NetNTLMv2 hashes are very useful once cracked, but ***cannot be used*** for techniques such as ***pash-the-hash***.

## NTLMv2

Se puede crackear offline

# RESPONDER

Se usa para envenenar trafico

> sudo responder -I ens224 




