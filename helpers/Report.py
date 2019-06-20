import copy

import xmltodict
from bs4 import BeautifulSoup


class Report:

    def __init__(self, xml_file_names, folder, foundhosts_dic, cidr_ranges):

        """
        Compiles all saved XML file into a HTML report

        :param xml_file_names: A list of saved XML files
        :param subnets: A list of subnets that were scanned
        :param attacker_ip: The ip of where the scan originated
        """

        self.scan_data = self.openXMLFiles(xml_file_names)
        self.host_table_template = self.getBS('helpers/templates/host_table.html')
        self.subnet_table = self.getBS('helpers/templates/subnet_table.html')
        self.report = self.getBS('helpers/templates/Final_Report.html')
        self.save_path = folder
        self.foundhosts_dic = foundhosts_dic
        self.cidr_ranges = cidr_ranges
        self.generateReport(self.save_path)


    def getBS(self, filename):
        """
        Opens HTML file and returns a BeautifulSoup object
        :param filename: path for xml
        :return: BeautifulSoup
        """
        with open(filename)as f:
            html = BeautifulSoup(f, 'html.parser')
        return html

    def openXMLFiles(self, filenames):
        """
        Opens all XML files and saves them as dics in list

        :param filenames: list of XMl file paths
        :return: list [ dic ]
        """
        xml_docs = []
        for filename in filenames:
            with open(filename) as fd:
                xml_doc = xmltodict.parse(fd.read())

            xml_docs.append(xml_doc)

        return xml_docs

    def generateReport(self, file_path):

        """
        Generates main HTML report

        :param file_path: path to save report
        :return: None
        """

        #  Adds subnets to CIDR ranges
        self.report.find(id='cidr_ranges').string = ', '.join([subnet.compressed for subnet in self.cidr_ranges])

        subnet_table = self.generateSubnetTable()

        if subnet_table:
            self.report.find(id='subnet_reports').append(subnet_table)

        self.saveReport(file_path)

    def generateSubnetTable(self):

        """
        Generates Tables for each subnet
        :param subnet:
        :param scan_results: Results from Nmap scan as dic
        :return:
        """

        subnet_table = copy.copy(self.subnet_table)

        if not self.scan_data :
            subnet_table.find(class_="description").string = "The network segment defined within the Scope of Work as a " \
                                                             "target IPv4 range for segmentation can not be reached from" \
                                                             " a network device hosted within a non-CDE network."

            subnet_table.find(class_="recommendation").string = "N/A"
            subnet_table.find(class_="risk").string = "N/A"

        ip_list = subnet_table.find(class_='found_ip')

        # Populates the Found Hosts
        for range in self.foundhosts_dic:
            for host in self.foundhosts_dic[range]:
                newtag = subnet_table.new_tag('li')
                newtag.string = host
                ip_list.append(newtag)

        #  For all found hosts generate a table for them and insert them into "ScreenShots"
        for scan_results in self.scan_data:

            try:
                hosts = scan_results['nmaprun']["host"]

                if isinstance(hosts, dict):
                    table = self.generateScreenShotTable(hosts)
                    subnet_table.find(class_="hosts").append(table)
                else:
                    for host in hosts:
                        if host["status"]["@state"] == "up":
                            table = self.generateScreenShotTable(host)
                            subnet_table.find(class_="hosts").append(table)

            except KeyError:
                pass

        return subnet_table

    def generateScreenShotTable(self, host):

        """
        Generates tables for all found hosts on subnets
        :param host: host xml data
        :return: HTML
        """

        table = copy.copy(self.host_table_template)

        target_ip = host["address"]["@addr"]
        open_ports = self.getOpenPorts(host)
        os_detected = self.getTopOS(host)

        table.find(class_='host_ip').string = target_ip

        for port in open_ports:
            li_new_tag = table.new_tag('li')
            li_new_tag.string = port
            table.find(class_='open_ports').append(li_new_tag)

        for os in os_detected:
            li_new_tag = table.new_tag('li')
            li_new_tag.string = os
            table.find(class_='os_detection').append(li_new_tag)

        return table

    def saveReport(self, output_folder):
        path = "output/%s/Final_Report.html" % output_folder
        with open(path, "w") as file:
            file.write(str(self.report))

    def getOpenPorts(self, host):
        try:
            ports = host["ports"]['port']

            if isinstance(ports, dict):
                return [ports['@portid'] + ':' + ports['service']['@name']]

            port_info = []
            for port in ports:
                port_info.append(port['@portid'] + ':' + port['service']['@name'])

            return port_info

        except KeyError:
            return ["No open Ports Found"]

    def getTopOS(self, host):
        try:
            os_match = host["os"]['osmatch']

            if isinstance(os_match, dict):
                os_name = str(os_match["@name"])
                os_accry = str(os_match['@accuracy'])
                return [os_name + " : " + os_accry]

            os_info = []
            count = 0
            for os in os_match:
                if count == 3:
                    return os_info
                os_name = str(os['@name'])
                os_accry = str(os['@accuracy'])
                os_info.append(os_name + " : " + os_accry)
                count += 1

            return os_info

        except KeyError:
            return ["No OS detected"]