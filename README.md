# Cyber Security für Entwickler - Java User Group IN //08.12.2020

## Agenda

1. [Intro](#intro)
2. [OWASP Top 10](#owasp-top-10)
3. [Saftladen](#saftladen)
4. [Tools](#tools)

---

## Intro

![Simon Trockel](img/profil.jpg "Simon Trockel")

### Simon Trockel

- Bachelor of Science Informatik (Wirtschaft)
- CISSP
- Softwareentwickler seit 2008
- Cyber Security Berater seit 2015

---

## [OWASP Top 10](https://owasp.org/www-project-top-ten/)

**1. Injection:** Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

**2. Broken Authentication:** Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities temporarily or permanently.

**3. Sensitive Data Exposure:** Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.

**4. XML External Entities (XXE):** Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks.

**5. Broken Access Control:** Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users’ accounts, view sensitive files, modify other users’ data, change access rights, etc.

**6. Security Misconfiguration:** Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion.

**7. Cross-Site Scripting (XSS):** XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.

**8. Insecure Deserialization:** Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.

**9. Using Components with Known Vulnerabilities:** Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.

**10. Insufficient Logging & Monitoring:** Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.

---

## [Saftladen](https://owasp.org/www-project-juice-shop/)

```ps
# Run at own risk! Do not set NODE_ENV to unsafe in Cloud Environments
docker run --rm -p 3000:3000 -e NODE_ENV=unsafe bkimminich/juice-shop:latest
```

### Normale Benutzung

- Account anlegen
- Eine Bestellung abschließen
- Bissl rumklicken

### SQL Injection & Broken Auth

[Login](http://localhost:3000/#/login) kaputt machen:

1. User ohne Email anlegen
2. Login ohne Passwort
3. Login als Admin
4. SQL Injection

<details>
<summary>Lösung</summary>

1. Email Validierung ist Client Seitig -> API Call direkt
2. Zuerst Testen ob SQL Injection möglich ist mit `'` als Username. Dann mal in den Error Logs suchen gehen.
   SQL Error gefunden? wie wäre es mit `Alice' --`
3. Login als Admin mit `' OR true --`

</details>

### Sensitive Data Exposure

1. JWT in `POST 'http://localhost:3000/rest/user/login'`
2. [Customer Feedback](http://localhost:3000/#/contact) & [About](http://localhost:3000/#/about)

<details>
<summary>Lösung</summary>

1. Das `POST` gibt ein JWT zurück. Allerdings enthält es mehr Informationen als nötig(und sinnvoll). Insbesondere den MD5 Hash des Passworts.
   [JWT.io](https://jwt.io)
   [MD5 Decrypt](https://www.md5online.org/md5-decrypt.html)
   MD5 sollte nicht zum hashen von Passwörtern genutzt werden. Lässt sich einfach berechnen und es gibt Kollisionen. [Mehr Infos](https://stackoverflow.com/questions/15774418/can-i-improve-the-security-of-md5-hashed-passwords-by-salting-the-existing-md5-h)
2. Emails werden nur bedingt maskiert. Die unmaskierten sind leicht zu raten

</details>

[Metrics](http://localhost:3000/metrics)

### Broken Access Control

Es ist Weihnachtszeit. Meine Frau hat für mich im Juice Shop bestellt. Aber ich bin ungeduldig und will wissen was Sie mir schenkt. Wenn ich mir nur die Bestellungen der anderen ansehen könnte...

<details>
<summary>Lösung</summary>

1. Basket anlegen
2. Dev Tools -> Application -> Session Storage -> `bid` verändern
3. Wo wir dabei sind -> API Calls in INSOMNIA ausprobieren

</details>

### Security Misconfiguration

Aber es geht noch viel einfacher... Was wäre wenn ich einfach alle Bestellungen sehen könnte...

<details>
<summary>Lösung</summary>

[Order](http://localhost:3000/ftp/order_e5c1-44e7ea88d0de11dd.pdf)
[FTP](http://localhost:3000/ftp)
[API Docs](http://localhost:3000/api-docs)

BONUS: Mehr Infos können mit `%2500.md` heruntergeladen werden. Siehe [http://localhost:3000/ftp/package.json.bak%2500.md](http://localhost:3000/ftp/package.json.bak%2500.md)

</details>

### XSS

#### DOM XSS

[Search](<http://localhost:3000/#/search?q=%3Ciframe%20src%3D%22javascript:alert('JUG%20IN%20RULEZ!!!!111elf');%22%3E>)

#### Reflected XSS

[Order History](http://localhost:3000/#/order-history)
[Track Order](http://localhost:3000/#/track-result?id=e5c1-a7c69c5f52842538)
[XSS](<http://localhost:3000/#/track-result?id=%3Ciframe%20src%3D%22javascript:alert('JUG%20IN%20RULEZ!!!!111elf');%22%3E>)

### Insecure Deserialization

Schaut es euch selber an. Sprengt den Rahmen für heute Abend.

### Known Vulnerabilities

Die verwendete JWT Lib ist verwundbar (siehe package.json)

<details>
<summary>Lösung</summary>

Wir können auch unsignierte Token senden:
[sig](<https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9-_')&input=eyJ0eXAiOiAiSldUIiwiYWxnIjogIm5vbmUifQ>)
[data](<https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)To_Base64('A-Za-z0-9-_')&input=ewogICJzdGF0dXMiOiAic3VjY2VzcyIsCiAgImRhdGEiOiB7CiAgICAiaWQiOiA0NzExLAogICAgInVzZXJuYW1lIjogIiIsCiAgICAiZW1haWwiOiAiand0bjNkQGp1aWNlLXNoLm9wIiwKICAgICJwYXNzd29yZCI6ICI4MjdjY2IwZWVhOGE3MDZjNGMzNGExNjg5MWY4NGU3YiIsCiAgICAicm9sZSI6ICJjdXN0b21lciIsCiAgICAiZGVsdXhlVG9rZW4iOiAiIiwKICAgICJsYXN0TG9naW5JcCI6ICIiLAogICAgInByb2ZpbGVJbWFnZSI6ICIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsCiAgICAidG90cFNlY3JldCI6ICIiLAogICAgImlzQWN0aXZlIjogdHJ1ZSwKICAgICJjcmVhdGVkQXQiOiAiMjAyMC0xMi0wNiAxODozODoyNy41MTEgKzAwOjAwIiwKICAgICJ1cGRhdGVkQXQiOiAiMjAyMC0xMi0wNiAxODozOTowMi43NjUgKzAwOjAwIiwKICAgICJkZWxldGVkQXQiOiBudWxsCiAgfSwKICAiaWF0IjogMTYwNzI5MjE5OSwKICAiZXhwIjogMTYwOTQ1OTE5OQp9>)

</details>

---

## Tools

### Präsentation

Tools und Resourcen während der Präsentation:

- [VS Code](https://code.microsoft.com)
- [Insomnia](https://insomnia.rest/)
- [JWT.io](https://JWT.io)
- [Cyber Chef](https://gchq.github.io/CyberChef/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP JuiceShop](https://owasp.org/www-project-juice-shop/)
- [Pwning JuiceShop](https://pwning.owasp-juice.shop/)

### Pipeline Tools

Folgende Tools können in euer Build/Deployment Pipeline eingebaut werden und helfen die gängigsten Fehler zu finden:

|                                   Tool                                    | Beschreibung                                                                                                  |
| :-----------------------------------------------------------------------: | ------------------------------------------------------------------------------------------------------------- |
|                   [Dependabot](https://dependabot.com/)                   | Dependabot schickt euch automatisch PRs für neue Versionen eurer Dependencies                                 |
|                     [TestSSL.sh](https://testssl.sh)                      | CLI zum scannen von TLS Settings eines Hosts. Quasi [Qualys SSL](https://www.ssllabs.com/index.html) als CLI. |
|            [GitLeak](https://github.com/zricethezav/gitleaks)             | Erkennt commited secrets und haut euch auf die Finger                                                         |
|       [npm Audit](https://docs.npmjs.com/cli/v6/commands/npm-audit)       | Dependency Check für NPM                                                                                      |
|       [yarn Audit](https://classic.yarnpkg.com/en/docs/cli/audit/)        | Dependency Check für yarn                                                                                     |
| [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) | Dependency Check von OWASP                                                                                    |

### Vulnerability Scanning und Pentesting

Folgende Tools können euch helfen Schwachstellen in eurer App zu entdecken. Auch ohne fortgeschrittene Hacking-Tricks:

|                        Tool                        | Beschreibung                                                      |
| :------------------------------------------------: | ----------------------------------------------------------------- |
|             [NMap](https://nmap.org/)              | CLI für NetzwerkScans, inkl. Port & OS Erkennung                  |
|        [OpenVAS](https://www.openvas.org/)         | OpenSource Vulnerability Scanner. Gibts auch als CLI afaik.       |
| [OWASP Zed Attack Proxy](https://www.zaproxy.org/) | Proxy für den lokalen Test                                        |
|           [Shodan.io](https://Shodan.io)           | Suchmaschine für kaputte Hosts im Internet (Webcams, Raspi, etc.) |

### Andere Tools/Links

- [Threagile](https://threagile.io) Agile Thread Modeling
- [Evil User Stories]() Als ein Angreifer kann ich böse Sachen in die URL schreiben und somit auf Dinge zugreifen oder deine User angreifen.
- [Cyber Security Evaluation Tool]() der CISA
