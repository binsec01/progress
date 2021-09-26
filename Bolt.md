Machine | Details
-----|----
Name | Bolt
OS| Linux
IP| 10.10.11.104
Difficulty | MEDIUM 


---------------

### NMAP:
```bash
# Nmap 7.91 scan initiated Sun Sep 26 07:16:55 2021 as: nmap -vvv -p 22,80,443 -sC -sV -oN initial_scan.txt 10.129.208.114
Nmap scan report for 10.129.208.114
Host is up, received syn-ack (0.31s latency).
Scanned at 2021-09-26 07:16:56 +06 for 38s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDkj3wwSWqzkYHp9SbRMcsp8vHlgm5tTmUs0fgeuMCowimWCqCWdN358ha6zCdtC6kHBD9JjW+3puk65zr2xpd/Iq2w+UZzwVR070b3eMYn78xq+Xn6ZrJg25e5vH8+N23olPkHicT6tmYxPFp+pGo/FDZTsRkdkDWn4T2xzWLjdq4Ylq+RlXmQCmEsDtWvNSp3PG7JJaY5Nc+gFAd67OgkH5TVKyUWu2FYrBc4KEWvt7Bs52UftoUTjodRYbOevX+WlieLHXk86OR9WjlPk8z40qs1MckPJi926adEHjlvxdtq72nY25BhxAjmLIjck5nTNX+11a9i8KSNQ23Fjs4LiEOtlOozCFYy47+2NJzFi1iGj8J72r4EsEY+UMTLN9GW29Oz+10nLU1M+G6DQDKxoc1phz/D0GShJeQw8JhO0L+mI6AQKbn0pIo3r9/hLmZQkdXruJUn7U/7q7BDEjajVK3gPaskU/vPJRj3to8g+w+aX6IVSuVsJ6ya9x6XexE=
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF5my/tCLImcznAL+8z7XV5zgW5TMMIyf0ASrvxJ1mnfUYRSOGPKhT8vfnpuqAxdc5WjXQjehfiRGV6qUjoJ3I4=
|   256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxr2nNJEycZEgdIxL1zHLHfh+IBORxIXLX1ciHymxLO
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 76362BB7970721417C5F484705E5045D
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 82C6406C68D91356C9A729ED456EECF4
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Issuer: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-24T19:11:23
| Not valid after:  2022-02-24T19:11:23
| MD5:   3ac3 4f7c ee22 88de 7967 fe85 8c42 afc6
| SHA-1: c606 ca92 404f 2f04 6231 68be c4c4 644f e9ed f132
| -----BEGIN CERTIFICATE-----
| MIIDozCCAougAwIBAgIUWYR6DcMDhx5i4CpQ5qkkspuUULAwDQYJKoZIhvcNAQEL
| BQAwYTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEaMBgGA1UEAwwRcGFzc2JvbHQuYm9s
| dC5odGIwHhcNMjEwMjI0MTkxMTIzWhcNMjIwMjI0MTkxMTIzWjBhMQswCQYDVQQG
| EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk
| Z2l0cyBQdHkgTHRkMRowGAYDVQQDDBFwYXNzYm9sdC5ib2x0Lmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBALPBsFKzUPba5tHWW85u/Do3CkSsUgWN
| Wp5ZShD3T3hRX+vxFjv0zVZaccLhY8gsoTaklvFZVrguU6rIKHCFpRt7JLSPCmx3
| /Dy8id1Fm3VgRStVcMdXFnWne3lZaw9cSqdAxzb6ZcERAZRlIOPj29zO5UIwvwTW
| FJwybndHlxZ9Y8TUT7O1z5FFNKMl/QP6DBdkDDTc+OQ9ObyYHd6zBdwfuJykX8Md
| 3ejO1n38j8zXhzB/DEwKVKqFqvm7K28OBOouOaHnqM5vO5OVEVNyeZhaOtX1UrOm
| c+B8RSHDU7Y7/6sbNxJGuwpJZtovUa+2HybDRJl92vnNeouddrdFZc0CAwEAAaNT
| MFEwHQYDVR0OBBYEFCjzBazWUuLcpQnqbcDsisjmzvYzMB8GA1UdIwQYMBaAFCjz
| BazWUuLcpQnqbcDsisjmzvYzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
| BQADggEBAA2qDGXEgqNsf4XqYqK+TLg+pRJ/rrdAFtxNwn8MYQv4ZlyouQsN2zPm
| t/dXls0iba1KvgYrt5QGWGODI8IkaujEDC452ktOmmi9+EnpK9DjKoKfCTL4N/ta
| xDZxR4qHrk35QVYB8jYVP8S98gu5crTkAo9TGiHoEKPvinx+pA9IHtynqh9pBbuV
| /micD+zMBVlZ50MILbcXqsBHRxHN4pmbcfc4yEOanNVJD3hmGchcyAFx2RLPsl36
| +QrGlwqpP7Bn7wzVCuxzQUWlA9VwVZKHYVVvCekvVP9DKL6FfI5avLgJJujQTqKw
| +uYRUUWj+CdI1oxxYt0SdimXHr81SgE=
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 26 07:17:34 2021 -- 1 IP address (1 host up) scanned in 38.66 seconds

```

### Port 80:
- CMS Name : AdminLTE - Free admin dashboard
- CMS Version : 
 
[github project](https://github.com/ColorlibHQ/AdminLTE.git)	

![[Admin_LTE.png]]

---------
#### CONTENT FUZZing:
```bash
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt  -u http://bolt.htb/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________


register                [Status: 200, Size: 11038, Words: 3053, Lines: 199]
login                   [Status: 200, Size: 9287, Words: 2135, Lines: 173]
contact                 [Status: 200, Size: 26291, Words: 10060, Lines: 468]
download                [Status: 200, Size: 18568, Words: 5374, Lines: 346]
logout                  [Status: 302, Size: 209, Words: 22, Lines: 4]
services                [Status: 200, Size: 22441, Words: 7170, Lines: 405]
pricing                 [Status: 200, Size: 31723, Words: 11055, Lines: 549]
sign-in                 [Status: 200, Size: 9287, Words: 2135, Lines: 173]
sign-up                 [Status: 200, Size: 11038, Words: 3053, Lines: 199]
check-email             [Status: 200, Size: 7331, Words: 1224, Lines: 147]
:: Progress: [43003/43003] :: Job [1/1] :: 138 req/sec :: Duration: [0:05:29] :: Errors: 0 ::

```

`/download` page has a downloadable docker image file.

![[bolt-docker_image.png]]

[Download Docker image file](http://bolt.htb/uploads/image.tar)

### `/login` page screenshot:
![[Login page.png]]

- I entered random username and password . It returns `403 FORBIDDEN` Error.
	- username=`admin `and password=`password`

![[403 Forbidden on login function.png]]

- Then I move forward to `/register` page. but When I try to create account on this domain. Server Can't process that request. and It's print `500 INTERNAL ERROR`.

![[internal server error on register function.png]]


### PORT 443: 
- CMS Name: Password Bolt - Open source password manager.
- CMS Version: 

[Password Bolt github project](https://github.com/passbolt/passbolt_api)

-------------
### Web Content Enumeration:

```bash
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt  -u https://10.129.208.114:443/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

css                     [Status: 301, Size: 178, Words: 6, Lines: 8]
login                   [Status: 301, Size: 0, Words: 1, Lines: 1]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8]
register                [Status: 301, Size: 0, Words: 1, Lines: 1]
img                     [Status: 301, Size: 178, Words: 6, Lines: 8]
logout                  [Status: 301, Size: 0, Words: 1, Lines: 1]
app                     [Status: 302, Size: 0, Words: 1, Lines: 1]
users                   [Status: 302, Size: 0, Words: 1, Lines: 1]
resources               [Status: 302, Size: 0, Words: 1, Lines: 1]
fonts                   [Status: 301, Size: 178, Words: 6, Lines: 8]
groups                  [Status: 302, Size: 0, Words: 1, Lines: 1]
recover                 [Status: 301, Size: 0, Words: 1, Lines: 1]
.json                   [Status: 401, Size: 233, Words: 5, Lines: 1]
locales                 [Status: 301, Size: 178, Words: 6, Lines: 8]
healthcheck             [Status: 403, Size: 3738, Words: 773, Lines: 88]
roles                   [Status: 302, Size: 0, Words: 1, Lines: 1]
:: Progress: [43003/43003] :: Job [1/1] :: 45 req/sec :: Duration: [0:14:51] :: Errors: 0 ::

```
