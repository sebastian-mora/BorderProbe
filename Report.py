from bs4 import BeautifulSoup
import copy
import xmltodict

class Report:

    def __init__(self, xml_file_name):

        """

        :param scan_data: Python dic
        """
        self.scan_data = self.openXML(xml_file_name)
        self.table_template = self.getBS('output/template/table_temp.html')
        self.report = self.getBS('output/template/report.html')

        self.generateReport()

    def getBS(self, filename):
        with open(filename)as f:
            html = BeautifulSoup(f, 'html.parser')
        return html

    def openXML(self, filename):
        with open(filename) as fd:
            xml_doc = xmltodict.parse(fd.read())
        return xml_doc
    def generateReport(self):

        try:
            hosts = self.scan_data['nmaprun']["host"]

            if isinstance(hosts, dict):
                table = self.generateTable(hosts)
                self.report.find(id="reports").append(table)
            else:
                for host in hosts:
                    if host["status"]["@state"] == "up":
                        table = self.generateTable(host)
                        self.report.find(id="reports").append(table)

            self.saveReport()


        except:
            print("No Hosts in this file")
            return None

    def saveReport(self):
        with open("output/report.html", "w") as file:
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



    def generateTable(self, host):
        table = copy.copy(self.table_template)

        target_ip = host["address"]["@addr"]
        open_ports  = self.getOpenPorts(host)
        os_detected = self.getTopOS(host)

        for target in table.findAll('span', class_='target'):
            target.string = target_ip

        #TODO FAILED HERE
        for port in open_ports:
            li_new_tag = table.new_tag('li')
            li_new_tag.string = port
            table.find(id='open-ports').append(li_new_tag)

        for os in os_detected:
            li_new_tag = table.new_tag('li')
            li_new_tag.string = os
            table.find(id='os_detection').append(li_new_tag)

        return table










