import random
import menus

class Scanner:

    def __init__(self,subnet_list):
        self.subnets = subnet_list


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


    def evasionTecs(self):
        tech_string = ''
        options={
            1: '',
            2: '-f',
            3: '-D'
        }
        menus.hostDiscovEvasionTech()
        choice = str(input())
        choice = list(map(int,choice.split(',')))

        for num in choice:

            if num in options:

                if options[num] is '-D':
                    decoys = input("Please enter Decoys <Decoy 1>, <Decoy 2>, ... , <You> ")
                    tech_string+= options[num] + " " + decoys
                else:
                    tech_string+= options[num] + " "
            else:
                print("invaild choice: %s", num)

        print(tech_string)

        return tech_string