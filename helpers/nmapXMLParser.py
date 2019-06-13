import datetime

import xmltodict


# TODO  <Runstat> at end of XML is not accurate

class nmapXMLParser:
    """
    This class Creates one main Nmap XML doc to which more scans can be appended then saved.
    """

    def __init__(self, doc=None):

        """

        :param doc: XML document. If not doc is provied a new doc will be created
        """

        self.main_doc = self.openXml(doc)

    def cleanXmlOutput(self, xml_data):
        """
        Takes XML output from Nmap and cleans Chars from STDOUT

        :param xml_data: Nmap output
        :return: Return XML in String
        """
        clean = str(xml_data)
        clean = clean.replace('\\n', '')
        clean = clean.replace("b'", '')
        clean = clean.replace("'", '')
        clean = clean[clean.index("<nmaprun"):]
        return clean

    def openXml(self, file_name):

        """
        Open XMl from file and parses it into a dict
        :param file_name: Xml File
        :return: Xml in python dic format
        """

        if file_name is None:
            return None

        else:
            with open(file_name)as fd:
                xml_doc = xmltodict.parse(fd.read())

            return xml_doc

    def saveAsXml(self):

        """
        Saves self.main_doc to XML file
        :return:
        """

        if self.main_doc is not None:
            date = datetime.datetime.now()
            filename = date.strftime('output/%X/LiveHosts.Xml')
            f = open(filename, 'w')

            f.writelines(xmltodict.unparse(self.main_doc))

    def getXmlAsDic(self, xml_string):
        return self.main_doc

    def getLiveHosts(self, xml_string):
        """
        Take Nmap xml output and return a list of Live host ips
        :param xml_string:
        :return: list(ipv4)
        """
        data = xmltodict.parse(self.cleanXmlOutput(xml_string))

        try:
            hosts = data['nmaprun']["host"]

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

    def appendScan(self, xml_string):
        """
        Takes Nmap Xml data in string and appends it to the xml_main doc
        :param xml_string:
        :return:
        """
        data = xmltodict.parse(self.cleanXmlOutput(xml_string))

        if self.main_doc is None:
            self.main_doc = data

            try:
                hosts = self.main_doc['nmaprun']["host"]

                if isinstance(hosts, dict):
                    self.main_doc['nmaprun'].update({'host': [hosts]})

            except:
                self.main_doc['nmaprun'].update({'host': []})


        else:
            try:
                hosts = data['nmaprun']["host"]

                if isinstance(hosts, dict):
                    self.main_doc['nmaprun']['host'].append(hosts)

                else:
                    for host in hosts:
                        self.main_doc['nmaprun']['host'].append(host)
            except:
                pass
