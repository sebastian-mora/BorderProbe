import random
import subprocess
import menus
from nmapXMLParser import nmapXMLParser as Parser


# Host Discovery Techniques https://nmap.org/book/host-discovery-strategies.html

class Scanner:

    def __init__(self, subnet):

        self.subnets = self.divideSubnet(subnet, 1)

        self.evasionOptions = {
            1: '',
            2: '-f',
            3: self.getDecoys,
            4: self.getTiming,
            5: self.getSpoofIP,
            6: self.getSpoofMac,
            7: '--randomize-hosts'
        }

    def randomizeSubnetOrder(self):
        """
        Takes the subnet list and shuffles the items
        :param subnets: list of subnets
        :return: list[subnets]
        """
        shuffled_subnets = list(self.subnets)
        random.shuffle(shuffled_subnets)
        return shuffled_subnets

    def divideSubnet(self, ipv4_subnet, prefix_len=1):
        """
        TODO: Add Check for Subnets 26>
        Divides subnet into /x where x is x=x+4
        :param ipv4_subnet:
        :return: list[Pv4sNetworks]
        """

        return list(ipv4_subnet.subnets(prefixlen_diff=prefix_len, new_prefix=None))

    def getDecoys(self):
        decoys = input("Please enter Decoys <Decoy 1>, <Decoy 2>, ... , <You> ")
        decoy_list = ["-D"]
        decoy_list.extend(decoys.split(","))
        return decoy_list

    def getTiming(self):
        menus.timingOptions()
        num = input("Pleas enter a Number: ")
        timing = ['-T']
        timing.append(str(num))
        return timing

    def getSpoofIP(self):
        ip = input("Please Enter Spoof IP: ")
        flags = ['-S', ip]
        return flags

    def getSpoofMac(self):

        """
        Gens random Unicast Mac
        https://stackoverflow.com/questions/8484877/mac-address-generator-in-python

        :return:
        """
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                           random.randint(0, 255),
                                           random.randint(0, 255))
        flags = ['--spoof-mac', mac]

        return flags

    def getLiveHosts(self, host_scan_results):

        """
        Uses the complied Host Disovery scan to find live hosts
        :return: list of host ips
        """
        live_hosts = []

        try:
            hosts = host_scan_results['nmaprun']["host"]
            count = 0

            for host in hosts:
                if host["status"]["@state"] == "up":
                    print("Host %s is up!" % host["address"]["@addr"])
                    live_hosts.append(host["address"]["@addr"])
                    count += 1

            print("Number of Live Hosts discovered: %d" % count)
            return live_hosts

        except:
            print("No Hosts in this file")
            return None



    def evasionTechniques(self):
        """
        Parses the user input into a Nmap flags
        :return: string
        """
        flag_list = []

        menus.hostDiscovEvasionTech()
        choice = input()
        choice = list(map(int, choice.split(',')))

        for item in choice:
            if item in self.evasionOptions:
                if callable(self.evasionOptions[item]):

                    flag_list.extend(self.evasionOptions[item]())

                else:
                    flag_list.append(self.evasionOptions[item])
            else:
                print("invaild choice: %s", item)

        return flag_list

    def hostPingScan(self):
        # nmap -sn subnet

        parser = Parser()

        for subnet in self.randomizeSubnetOrder():
            result = self.executeNmapCommand(['-sn','-PE', '-R', "-n", str(subnet)])

            parser.appendHostScan(result)

        parser.saveAsXml()  # Saves All scans into a single XML File
        host_scan_results = parser.getXmlAsDic()

        self.getLiveHosts(host_scan_results)

    def hostIpPing(self):
        # namp -n -sn --send-ip 192.168.33.37

        scan_flags = ['-n', '-sn', '--send-ip']
        parser = Parser()

        for subnet in self.randomizeSubnetOrder():
            command = list(scan_flags)
            command.append(str(subnet))
            result = self.executeNmapCommand(command)
            parser.appendHostScan(result)

        parser.saveAsXml()
        host_scan_results = parser.getXmlAsDic()
        self.getLiveHosts(host_scan_results)
        return host_scan_results

    def hostCustomScan(self):

        # nmap -sn (no port) -PS22-25,80,3389 (SYN on common ports) -PA22-25,80,3389 (ACK on common ports) subnet

        port_check_flags = ['-sn', '-PS22-25,80,3389', '-PA22-25,80,3389']

        parser = Parser()

        flags = self.evasionTechniques()

        for subnet in self.randomizeSubnetOrder():
            flag_list = list(flags)
            flag_list.extend(port_check_flags)
            flag_list.append(str(subnet))
            result = self.executeNmapCommand(flag_list)
            parser.appendHostScan(result)

        parser.saveAsXml()
        host_scan_results = parser.getXmlAsDic()
        self.getLiveHosts(host_scan_results)

    # TODO Stage 2 Port Scan
    def stageTwoScan(self):
        pass

    def executeNmapCommand(self, flags):

        """
        Execute an Nmap command and
        :param flags: ex. ' -B -f -P22'
        :return: stdout
        """

        # adds the required flags to the start of the list
        flags.insert(0, "nmap")
        flags.insert(1, "-oX")
        flags.insert(2, '-')

        print(flags)

        # Starts the Nmap Process
        p = subprocess.Popen(flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        menus.processAnimation(p)

        print("Scan Complete for: %s", flags[len(flags) - 1])
        stdout, stderr = p.communicate()

        return stdout
