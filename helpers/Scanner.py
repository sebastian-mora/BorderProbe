import datetime
import os
import random
import subprocess
import xmltodict
from helpers import menus


class Scanner:

    def __init__(self):

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

        self.folder = None

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
        prefix_len = ipv4_subnet.prefixlen

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
        timing = ['-T', str(num)]
        return timing

    def getSpoofIP(self):
        ip = input("Please Enter Spoof IP: ")
        flags = ['-S', ip]
        return flags

    def saveLiveHosts(self, live_hosts, subnet, foldername):

        """
        Saves live hosts to a CSV
        CSV format: ip,subnet

        :param live_hosts: list of found hosts
        :param subnet: the subnet the hosts were found on
        :param foldername: to where the csv will be saved
        :return:
        """

        if os.path.isdir('output/%s' % foldername) is not True:
            os.mkdir('output/%s' % foldername)

        filename = 'output/%s/LiveHosts.csv' % foldername
        f = open(filename, 'a+')

        for host in live_hosts:
            f.write("%s,%s\n" % (str(host), subnet))
        f.close()


    def getSpoofMac(self):

        """
        Gens random Unicast Mac

        :return: MAC Address str
        """
        mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                           random.randint(0, 255),
                                           random.randint(0, 255))
        flags = ['--spoof-mac', mac]

        return flags

    def getLiveHosts(self, host_scan_results):

        """
        Take Nmap xml output and return a list of Live host ips
        :param xml_string:
        :return: list(ipv4)
        """
        #  Turns xml into dic
        data = xmltodict.parse(host_scan_results)

        try:
            hosts = data['nmaprun']["host"]

            #  If only one host found result will be in dic not list
            if isinstance(hosts, dict):
                ip = hosts['address']['@addr']
                return [ip]

            else:
                hosts = data['nmaprun']['host']
                live_hosts = []
                for host in hosts:
                    live_hosts.append(host['address']['@addr'])

                return live_hosts


        except:
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
                print("Invalid choice: %s", item)

        self.evasion_used = flag_list

        return flag_list

    def hostScan(self, subnets, scan_selector):
        """
        Discovers lives host

        :param subnets: list of all subnets to be scanned
        :param scan_selector: user chosen scan type
        :return: Dic {subnet: [found_host ip]}
        """

        scan_type = {
            1: ['-sn', '-PE', '-R', "-n", '-iL', '-'],  # Ping Scan
            2: ['-n', '-sn', '--send-ip', '-iL', '-'],  # Ip Scan
            3: ['-sn', '-PS22-25,80,3389', '-PA22-25,80,3389', '-iL', '-']  # Custom Scan
        }

        flags = scan_type[scan_selector]

        hosts = {}

        if scan_selector == 3:
            flags.extend(self.evasionTechniques())

        found_hosts = []
        folder_name = datetime.datetime.now().strftime('%X')
        self.folder = folder_name

        for subnet in subnets:
            subnet_div = self.divideSubnet(subnet)

            #  Shuffles the order in which the subnets are scanned
            for random_subnet in self.randomizeSubnetOrder(subnet_div):
                result = self.executeNmapCommand(flags, random_subnet.compressed)

                #  extract live hosts from xml data
                result = self.getLiveHosts(result)

                if result:
                    found_hosts.extend(result)

            self.saveLiveHosts(found_hosts, random_subnet.compressed, folder_name)
            hosts[subnet.compressed] = found_hosts
            found_hosts = []

        return hosts


    def phaseTwoScan(self, host_dic):
        """
        Using the dic of live host from the first scan
        This method will do a deeper scan using the
        flags (--randomize-hosts -n -Pn -A -sSVC (Phase 1 Evasion) --top-ports 1000 -iL -)
        *Any evasion Methods used in Phase one will also be applied

        :param host_dic: {subnet: [found_host ip]}
        :return: [xml_file_name, ... ]
        """
        # flags = ['--randomize-hosts', '-n', '-Pn', '-O', '-sV', '--top-ports', '1000',
        #           '--script-timeout', '20', '-iL', live_hosts_file]

        flags = ['--randomize-hosts', '-n', '-Pn', '--top-ports', '100', '--script-timeout', '20', '-iL', '-']
        saved_files = []

        if self.evasion_used:
            flags.extend(self.evasion_used)

        count = 0
        for subnet in host_dic:
            ips = ' '.join(host_dic[subnet])
            filename = 'output/%s/Scan_Results(%d).xml' % (self.folder, count)
            self.executeNmapCommand(flags, ips, filename)
            saved_files.append(filename)
            count += 1

        return saved_files

    def executeNmapCommand(self, flags, host_ips, file_name=None):

        """
            Takes flags and ip list and pipe it into Nmap. The Nmap result is returned in XMl format
            If a file name is specified it will save to it otherwise results will be returned on stdout

        :param flags: nmap flags
        :param host_ips: list of ips to be scanned
        :param file_name: (opt) where to save results
        :return: stdout
        """
        flags = flags.copy()
        # adds the required flags to the start of the list
        flags.insert(0, "nmap")
        flags.insert(1, "-oX")

        if file_name:
            flags.insert(2, file_name)

        else:
            flags.insert(2, '-')

        print(flags)

        # Starts the Nmap Process
        p = subprocess.Popen(flags, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(input=host_ips.encode())
        menus.processAnimation(p)

        # TODO add progress output

        # If nmap throws error print error and exit
        if "QUITTING" in str(stderr):
            print('\n' + str(stderr))

        return stdout