import random
import subprocess

import menus
from nmapXMLParser import nmapXMLParser as Parser


class Scanner:

    def __init__(self, subnet):

        self.subnets = self.divideSubnet(subnet)
        self.parser = Parser()

        self.host_scan_results = None

        self.evasionOptions = {
            1: '',
            2: '-f',
            3: self.getDecoys,
            4: self.getTiming(),
            5: '--randomize-hosts'
        }

    def radomizeSubnetOrder(self):
        """
        Takes the subnet list and shuffles the items
        :param subnets: list of subnets
        :return: list[subnets]
        """
        shuffled_subnets = list(self.subnets)
        random.shuffle(shuffled_subnets)
        return shuffled_subnets



    def divideSubnet(self, ipv4_subnet):
        """
        TODO: Add Check for Subnets 26>
        Divides subnet into /x where x is x=x+4
        :param ipv4_subnet:
        :return: list[Pv4sNetworks]
        """

        return list(ipv4_subnet.subnets(prefixlen_diff=1, new_prefix=None))

    def getDecoys(self):
        decoys = input("Please enter Decoys <Decoy 1>, <Decoy 2>, ... , <You> ")
        decoy_list = ["-D"]
        decoy_list.extend(decoys.split(","))
        return decoy_list

    def getTiming(self):
        time = input("Pleas enter a Number: ")
        return list(str(time))



#TODO Fix bug when host list is 1 object

    def getLiveHosts(self):

        """
        Uses the complied Host Disovery scan to find live hosts
        :return: list of host ips
        """

        live_hosts = []

        print(self.host_scan_results)
        try:
            hosts = self.host_scan_results['nmaprun']["host"]
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


    # TODO Still very buggy

    def evasionTecs(self):
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

        print(flag_list)

        return flag_list

    def pingOnlyScan(self):
        # nmap -sn subnet

        for subnet in self.radomizeSubnetOrder():
            result = self.executeNmapCommand(['-sn', '-R', "-n", str(subnet)])

            self.parser.appendScan(result)

        self.parser.saveAsXml()  # Saves All scans into a single XML File
        self.host_scan_results = self.parser.getXmlAsDic()

        self.getLiveHosts()

    def hostComboScan(self):

        # nmap -sn (no port) -PS22-25,80,3389 (SYN on common ports) -PA22-25,80,3389 (ACK on common ports) subnet
        flags = self.evasionTecs()

        for subnet in self.radomizeSubnetOrder():
            temp = list(flags)
            temp.append(str(subnet))
            print(temp)
            self.executeNmapCommand(temp)

    def executeNmapCommand(self, flags):

        """
        Execute an Nmap command and
        :param flags: ex. ' -B -f -P22'
        :return: stdout
        """

        #adds the reqired flags to the start of the list
        flags.insert(0, "nmap")
        flags.insert(1, "-oX")
        flags.insert(2, '-')

        print(flags)

        #Starts the Nmap Process
        p = subprocess.Popen(flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #menus.processAnimation(p)

        print("Scan Complete for: %s", flags[len(flags) - 1])
        stdout, stderr = p.communicate()

        return stdout
