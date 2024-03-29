
def headerAsciiArt():
    print("""
      /$$$$$$$                            /$$                           /$$$$$$$                     /$$                
     | $$__  $$                          | $$                          | $$__  $$                   | $$                
     | $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$       | $$  \ $$ /$$$$$$   /$$$$$$ | $$$$$$$   /$$$$$$ 
     | $$$$$$$  /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$      | $$$$$$$//$$__  $$ /$$__  $$| $$__  $$ /$$__  $$
     | $$__  $$| $$  \ $$| $$  \__/| $$  | $$| $$$$$$$$| $$  \__/      | $$____/| $$  \__/| $$  \ $$| $$  \ $$| $$$$$$$$
     | $$  \ $$| $$  | $$| $$      | $$  | $$| $$_____/| $$            | $$     | $$      | $$  | $$| $$  | $$| $$_____/
     | $$$$$$$/|  $$$$$$/| $$      |  $$$$$$$|  $$$$$$$| $$            | $$     | $$      |  $$$$$$/| $$$$$$$/|  $$$$$$$
     |_______/  \______/ |__/       \_______/ \_______/|__/            |__/     |__/       \______/ |_______/  \_______/


     """)


def startMenu():
    headerAsciiArt()

    print("""
        RUN AS ROOT!
        For large subnet it is recommend that you use screen to run in background 
        
        1. Scan Subnet

        2. Scan Subnets from File
        
        3. Generate Report from Nmap XML
        
    """)


def hostDiscoveryMethods():
    print("""
        Please Chose a Host Disovery method:
        
        1. ICMP Only Scan 
        2. IP Protocol Ping
        3. Custom Scan
    
    """)


def hostDiscovEvasionTech():
    print("""
        Please chose one or more methods (1,2,3,...)
        
        1. No evasion
        2. Fragmentation (Root Required)
        3. Decoy Scan 
        4. Timing 1-4
        5. Spoof Ip
        6. Spoof Mac
        7. Randomize Hosts
        
    """)


def timingOptions():
    print("""
        Timing Options:
        
        0: Paranoid
        1: Sneaky
        2: Polite
        3: Normal
        4: Aggressive
        5: Insane
        
    """)


def readInt():
    try:
        return int(input("Please Enter a Number: "))
    except ValueError:
        print("Input not an Integer")
