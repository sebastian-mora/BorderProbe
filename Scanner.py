import random
import subprocess

import menus


class Scanner:

    def __init__(self, subnet_list):

        self.subnets = subnet_list

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

    def pingOnlyScan(self):
        # nmap -sn subnet

        for subnet in self.radomizeSubnetOrder():
            self.executeCommand(['-sn', '-R', str(subnet)])
            # print(str(subnet))

    def hostComboScan(self):

        # nmap -sn (no port) -PS22-25,80,3389 (SYN on common ports) -PA22-25,80,3389 (ACK on common ports) subnet
        flags = self.evasionTecs()

        for subnet in self.radomizeSubnetOrder():
            temp = list(flags)
            temp.append(str(subnet))
            print(temp)
            self.executeCommand(temp)

    def getDecoys(self):
        decoys = input("Please enter Decoys <Decoy 1>, <Decoy 2>, ... , <You> ")
        decoy_list = ["-D"]
        decoy_list.extend(decoys.split(","))
        return decoy_list

    def getTiming(self):
        time = input("Pleas enter a Number: ")
        return list(str(time))

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

    def executeCommand(self, flags):

        """
        Execute an Nmap command and return the values
        :param flags: ex. ' -B -f -P22'
        :return: returns scan results in XML format
        """
        flags.insert(0, "nmap")

        print(flags)

        p = subprocess.Popen(flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        menus.processAnimation(p)

        stdout, stderr = p.communicate()
        print("Error: %s", stderr)
        print("Output: %s", stdout)

        return stdout
