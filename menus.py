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
        1. Scan Subnet

        2. Scan Subnets from File (not implemented)
    """)



def hostDiscoveryMethods():
    print("""
        Please Chose a Host Disovery method:
        
        1. ICMP Only Scan 
        2. Combination ICMP with TCP top 20 port
    
    """)

def hostDiscovEvasionTech():
    print("""
        Please chose one or more methods (1,2,3,...)
        
        1. No evasion
        2. Fragmentation
        3. Decoy Scan 
        
    """)

def readInt():
    return int(input("Please Enter a number "))