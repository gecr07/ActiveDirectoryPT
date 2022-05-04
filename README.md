# Active Directory Pentest

Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

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







