import requests , csv , subprocess

#source-Abuse CH
response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").text

rule = "netsh advfirewall firewall delete rule name = 'BadIP"
subprocess.run(["Powershell", "-command", rule])

mycsv = csv.readder(filler(lambda x:not x.startwith("#"),response.splitlines()))
for row in mycsv:
    ip = row[1]
    if(ip)!=("dst_ip"):
        print("Added rule to block:",ip)
        rule="netsh advfirewall firewall add rule name='BadIP' Dir=out Action=Block RemoteIP="+ip
        subprocess.run(["Powershell","-command", rule])