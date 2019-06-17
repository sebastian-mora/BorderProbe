import copy

import xmltodict
from bs4 import BeautifulSoup


class Report:

    def __init__(self, xml_file_names, subnets, attacker_ip):

        """
        Compiles all saved XML file into a HTML report

        :param xml_file_names: A list of saved XML files
        :param subnets: A list of subnets that were scanned
        :param attacker_ip: The ip of where the scan originated
        """
        self.attacker_ip = attacker_ip
        self.scan_data = self.openXMLFiles(xml_file_names)
        self.host_table_template = self.getBS('helpers/templates/host_table.html')
        self.subnet_table = self.getBS('helpers/templates/subnet_table.html')
        self.report = self.getBS('helpers/templates/Final_Report.html')
        self.save_path = xml_file_names[0].split('/')[xml_file_names[0].index("output") + 1]
        self.subnets = subnets
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
        self.report.find(id='cidr_ranges').string = ' '.join([subnet.compressed for subnet in self.subnets])

        report_num = 0
        for subnet in self.subnets:
            # Generates subnet table
            subnet_table = self.generateSubnetTable(subnet, self.scan_data[report_num])
            report_num += 1
            self.report.find(id='subnet_reports').append(subnet_table)

        self.saveReport(file_path)

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

    def generateSubnetTable(self, subnet, scan_results):

        """
        Generates Tables for each subnet
        :param subnet:
        :param scan_results: Results from Nmap scan as dic
        :return:
        """

        subnet_table = copy.copy(self.subnet_table)

        for ip in subnet_table.findAll('span', class_='target'):
            ip.string = subnet.compressed

        #  subnet_table.find(class_='attacker').string = self.attacker_ip

        #  For all found hosts generate a table for them and insert them into "ScreenShots"
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

            return subnet_table

        except:
            print("No Hosts in this file")
            return None

    def saveReport(self, output_folder):
        path = "output/%s/Final_Report.html" % output_folder
        with open(path, "w") as file:
            file.write(str(self.report))

    def getOpenPorts(self, host):
        try:
            ports = host["ports"]['port']
            port_info = []
            for port in ports:
                port_info.append(port['@portid'] + ':' + port['service']['@name'])

            return port_info

        except:
            return ["No open Ports Found"]

    def getTopOS(self, host):
        try:
            os_match = host["os"]['osmatch']
            os_info = []
            count = 0
            for os in os_match:
                if count == 3:
                    return os_info
                os_info.append(os['@name'] + ':' + os['@accuracy'] + '%')
                count += 1

            return os_info

        except:
            return ["No OS detected"]