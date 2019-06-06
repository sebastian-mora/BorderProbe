import random
import subprocess

import menus


class Scanner:

    def __init__(self,subnet_list):
        self.subnets = subnet_list
        self.evasionOptions = {
            1: '',
            2: '-f',
            3: self.getDecoys
        }


    def radomizeSubnetOrder(self,subnets):
        """
        Takes the subnet list and shuffles the items
        :param subnets: list of subnets
        :return: list[subnets]
        """
        return random.shuffle(subnets)


    def pingOnlyScan(self):
        #nmap -sn subnet
        pass

    def hostComboScan(self):

        # nmap -sn (no port) -PS22-25,80,3389 (SYN on common ports) -PA22-25,80,3389 (ACK on common ports) subnet
        self.evasionTecs()

        pass

    def getDecoys(self):
        decoys = input("Please enter Decoys <Decoy 1>, <Decoy 2>, ... , <You> ")
        return str("-D " + decoys)




    def evasionTecs(self):
        """
        Parses the user input into a Nmap flags
        :return: string
        """
        tech_string = ''

        menus.hostDiscovEvasionTech()
        choice = input()
        choice = list(map(int,choice.split(',')))

        for item in choice:

            if item in self.evasionOptions:

                if callable(self.evasionOptions[item]):

                    tech_string += self.evasionOptions[item]() + " "

                else:
                    tech_string += self.evasionOptions[item] + " "
            else:
                print("invaild choice: %s", item)

        print(tech_string)

        return tech_string

    def executeCommand(self, flags):

        """
        Execute an Nmap command and return the values
        :param flags: ex. ' -B -f -P22'
        :return: returns scan results in XML format
        """
        p = subprocess.Popen(['nmap', flags], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        menus.processAnimation(p)

        stdout, stderr = p.communicate()

        return stdout
