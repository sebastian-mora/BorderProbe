import random
import subprocess

import menus
from nmapXMLParser import nmapXMLParser as Parser


class Scanner:

    def __init__(self, subnet):

        self.subnets = self.divideSubnet(subnet)
        self.parser = Parser()

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

    # Todo Add check for subnets 26>

    def divideSubnet(self, ipv4_subnet):
        """
        Divides subnet into /x where x is x=x+4
        :param ipv4_subnet:
        :return: list[Pv4sNetworks]
        """

        return list(ipv4_subnet.subnets(prefixlen_diff=4, new_prefix=None))

    def getDecoys(self):
        decoys = input("Please enter Decoys <Decoy 1>, <Decoy 2>, ... , <You> ")
        decoy_list = ["-D"]
        decoy_list.extend(decoys.split(","))
        return decoy_list

    def getTiming(self):
        time = input("Pleas enter a Number: ")
        return list(str(time))

    # TODO This method is close to done. Finish after parser

    # def getLiveHostList(self, file):
    #     with open(file)as fd:
    #         doc = xmltodict.parse(fd.read())
    #
    #
    #     hosts = doc['nmaprun']["host"]
    #
    #     for host in hosts:
    #         if host["status"]["@state"] is "up":
    #             print(host[["address"]["@addr"]])





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
            stream = self.executeNmapCommand(['-sn', '-R', "-n", str(subnet)])
            stdout, stderr = stream.communicate()
            self.parser.appendScan(stdout)

        self.parser.save()

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
        Execute an Nmap command and Saves results in (date_nmap_scan.xml)
        :param flags: ex. ' -B -f -P22'
        :return: returns name of file
        """

        #adds the reqired flags to the start of the list
        flags.insert(0, "nmap")
        flags.insert(1, "-oX")
        flags.insert(2, '-')

        print(flags)

        p = subprocess.Popen(flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        menus.processAnimation(p)

        print("Scan Complete for: %s", flags[len(flags) - 1])

        return p
