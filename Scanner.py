import datetime
import random
import subprocess
import menus
from nmapXMLParser import nmapXMLParser as Parser


# Host Discovery Techniques https://nmap.org/book/host-discovery-strategies.html

class Scanner:

    def __init__(self, subnet):

        self.evasionOptions = {
            1: '',
            2: '-f',
            3: self.getDecoys,
            4: self.getTiming,
            5: self.getSpoofIP,
            6: self.getSpoofMac,
            7: '--randomize-hosts'
        }

        self.evasion_used = []

    def randomizeSubnetOrder(self, subnets):
        """
        Takes the subnet list and shuffles the items
        :param subnets: list of subnets
        :return: list[subnets]
        """
        shuffled_subnets = list(subnets)
        random.shuffle(shuffled_subnets)
        return shuffled_subnets

    def divideSubnet(self, ipv4_subnet):
        """

        Divides subnet into /24
        :param ipv4_subnet:
        :return: list[IPv4sNetworks]
        """
        subnet_string = str(ipv4_subnet)
        prefix_len = int(subnet_string[subnet_string.index('/') + 1:])
        print(prefix_len)

        if prefix_len < 24:
            prefix_len = 24 - prefix_len

        else:
            prefix_len = 0

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

    def saveLiveHosts(self, live_hosts):
        date = datetime.datetime.now()
        filename = date.strftime('output/%d_%X_LiveHosts.txt')
        f = open(filename, 'w')

        for host in live_hosts:
            f.write("%s\n" % str(host))
        f.close()
        return filename

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

        self.evasion_used = flag_list

        return flag_list

    def hostPingScan(self, subnet):
        # nmap -sn subnet

        """
        Uses ping only scan and saves result to txt file

        :param subnet: Full Subnet range
        :return: File name
        """

        parser = Parser()

        live_hosts = []

        for subnet in self.randomizeSubnetOrder(subnet):
            result = self.executeNmapCommand(['-sn', '-PE', '-R', "-n", str(subnet)])
            result = parser.getLiveHosts(result)

            if result:
                live_hosts.extend(result)

        file_name = self.saveLiveHosts(live_hosts)
        return file_name

    def hostIpPing(self, subnet):
        # namp -n -sn --send-ip 192.168.33.37

        """
        Uses ping only scan and saves result to txt file

        :param subnet: Full Subnet range
        :return: File name
        """

        scan_flags = ['-n', '-sn', '--send-ip']
        parser = Parser()

        live_hosts = []
        for subnet in self.randomizeSubnetOrder(subnet):
            command = list(scan_flags)
            command.append(str(subnet))
            result = self.executeNmapCommand(command)
            result = parser.getLiveHosts(result)

            if result:
                live_hosts.extend(result)

        file_name = self.saveLiveHosts(live_hosts)
        return file_name

    def hostCustomScan(self, subnet):

        """
        Uses ping only scan and saves result to txt file

        :param subnet: Full Subnet range
        :return: File name
        """

        # nmap -sn (no port) -PS22-25,80,3389 (SYN on common ports) -PA22-25,80,3389 (ACK on common ports) subnet
        # Check for SSH, Telnet, Ftp, RPC, Http, 445 (SMB), 135 (RPC), 139 (smb), 88 (Kerberos),

        port_check_flags = ['-sn', '-PS22-25,80,3389', '-PA22-25,80,3389']

        parser = Parser()

        flags = self.evasionTechniques()

        live_hosts = []

        for subnet in self.randomizeSubnetOrder(subnet):
            flag_list = list(flags)
            flag_list.extend(port_check_flags)
            flag_list.append(str(subnet))
            result = self.executeNmapCommand(flag_list)
            result = parser.getLiveHosts(result)

            if result:
                live_hosts.extend(result)

        file_name = self.saveLiveHosts(live_hosts)
        return file_name

    # TODO Stage 2 Port Scan
    def phaseTwoScan(self, live_hosts_file):

        """
            Using the list of live host from the first scan
            This method will do a deeper scan suing the
            flags (--randomize-hosts -n -Pn -A -sSVC (Phase 1 Evasion) --top-ports 1000 -iL filename-of-live-hosts.txt )
            *Any evasion Methods used in Phase one will also be applied

        :param live_hosts_file: Txt file will be passed to Nmap to scan
        :return: append results to XML Scan file
        """

        flags = ['--randomize-hosts', '-n', '-Pn', '-A', '-sV', '--top-ports', '1000', '-iL', live_hosts_file]

        if self.evasion_used:
            flags.extend(self.evasion_used)

        date = datetime.datetime.now()
        filename = date.strftime('%d_%X_Scan_Results.xml')

        self.executeNmapCommand(flags, filename)

    def executeNmapCommand(self, flags, file_name=None):

        """
        Execute an Nmap command.
        :param file_name: If file name is set method will save Nmap Result. If not result will be returned from stdout
        :param flags: ex. ' -B -f -P22'
        :return: stdout
        """

        # adds the required flags to the start of the list
        flags.insert(0, "nmap")
        flags.insert(1, "-oX")

        if file_name:
            flags.insert(2, file_name)
        else:
            flags.insert(2, '-')

        print(flags)

        # Starts the Nmap Process
        p = subprocess.Popen(flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        menus.processAnimation(p)

        print("Scan Complete for: %s" % flags[len(flags) - 1])
        stdout, stderr = p.communicate()

        # TODO BASIC BUT WORKS
        if "QUITTING" in str(stderr):
            print('\n' + str(stderr))

        return stdout
