
      /$$$$$$$                            /$$                           /$$$$$$$                     /$$                
     | $$__  $$                          | $$                          | $$__  $$                   | $$                
     | $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$       | $$  \ $$ /$$$$$$   /$$$$$$ | $$$$$$$   /$$$$$$ 
     | $$$$$$$  /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$      | $$$$$$$//$$__  $$ /$$__  $$| $$__  $$ /$$__  $$
     | $$__  $$| $$  \ $$| $$  \__/| $$  | $$| $$$$$$$$| $$  \__/      | $$____/| $$  \__/| $$  \ $$| $$  \ $$| $$$$$$$$
     | $$  \ $$| $$  | $$| $$      | $$  | $$| $$_____/| $$            | $$     | $$      | $$  | $$| $$  | $$| $$_____/
     | $$$$$$$/|  $$$$$$/| $$      |  $$$$$$$|  $$$$$$$| $$            | $$     | $$      |  $$$$$$/| $$$$$$$/|  $$$$$$$
     |_______/  \______/ |__/       \_______/ \_______/|__/            |__/     |__/       \______/ |_______/  \_______/



### Automated Network Segmentation Tester
 ___
 
 ####Description
 
 This tool automates subnet segmentation testing. The tool operates in three
 main phases. The first phase using a variety of Host discovery techniques as
 well as firewall evasion and save the live hosts to a csv file. The second
 phase then uses those hosts to do an in-depth port/service scan. In phase 3 
 the tool will auto generate an HTML finding report.
 ___
 

[x] Phase 1 (Host Discovery)

[x] Phase 2 (Port Scan on Discovered Hosts)

[X] Phase 3 Generate HTML Report 

---

Formatting for "Scan Subnets from File"

```
127.0.0.1/32
127.0.0.1/24
127.0.0.6/19
```