import copy

import xmltodict
from bs4 import BeautifulSoup


class Report:

    def __init__(self, xml_file_name, subnets, attacker_ip):

        """

        :param scan_data: Python dic
        """
        self.attacker_ip = attacker_ip
        self.scan_data = self.openXML(xml_file_name)
        self.table_template = self.getBS('output/template/table_temp.html')
        self.report = self.getBS('output/template/report.html')
        self.save_path = xml_file_name.split('/')[xml_file_name.index("output") + 1]
        self.subnets = subnets
        self.generateReport(self.save_path)

    def getBS(self, filename):
        with open(filename)as f:
            html = BeautifulSoup(f, 'html.parser')
        return html

    def openXML(self, filename):
        with open(filename) as fd:
            xml_doc = xmltodict.parse(fd.read())
        return xml_doc

    def generateReport(self, file_path):

        for subnet in self.subnets:

            self.report.find(id='cidr_ranges').string = ''.join(subnet)

            for ip in self.report.findAll('span', class_='target'):
                ip.string = subnet

            self.report.find(id='attacker').string = self.attacker_ip

            try:
                hosts = self.scan_data['nmaprun']["host"]

                if isinstance(hosts, dict):
                    table = self.generateScreenShotTable(hosts)
                    self.report.find(id="hosts").append(table)
                else:
                    for host in hosts:
                        if host["status"]["@state"] == "up":
                            table = self.generateScreenShotTable(host)
                            self.report.find(id="hosts").append(table)
            except:
                print("No Hosts in this file")
                return None

        self.saveReport(file_path)

    def saveReport(self, output_folder):
        path = "output/%s/report.html" % output_folder
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
            for os in os_match:
                os_info.append(os['@name'] + ':' + os['@accuracy'] + '%')

            return os_info

        except:
            return ["No OS detected"]

    def generateScreenShotTable(self, host):

        table = copy.copy(self.table_template)

        target_ip = host["address"]["@addr"]
        open_ports = self.getOpenPorts(host)
        os_detected = self.getTopOS(host)

        table.find(id='host_ip').string = target_ip


        for port in open_ports:
            li_new_tag = table.new_tag('li')
            li_new_tag.string = port
            table.find(id='open_ports').append(li_new_tag)

        count = 0
        for os in os_detected:
            if count == 3:
                break
            li_new_tag = table.new_tag('li')
            li_new_tag.string = os
            table.find(id='os_detection').append(li_new_tag)
            count += 1

        return table
