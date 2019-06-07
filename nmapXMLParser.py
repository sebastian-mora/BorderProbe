import datetime

import xmltodict


class nmapXMLParser:

    def __int__(self, doc=None):
        self.main_doc = self.openXml(doc)

    def cleanXmlOutput(self, xml_data):
        clean = str(xml_data)
        clean = clean.replace('\\n', '')
        clean = clean.replace("b'", '')
        clean = clean.replace("'", '')
        clean = clean[clean.index("<nmaprun"):]
        return clean

    def openXml(self, file_name):

        if file_name is None:
            return None

        else:
            with open(file_name)as fd:
                xml_doc = xmltodict.parse(fd.read())

            return xml_doc

    def saveXml(self):

        if self.main_doc is not None:
            date = datetime.datetime.now()
            filename = date.strftime('%d_%X_LiveHosts.xml')
            f = open(filename, 'w')
            f.writelines(xmltodict.unparse(self.main_doc))

    def appendScan(self, xml_string):
        data = xmltodict.parse(self.cleanXmlOutput(xml_string))

        if self.main_doc is None:
            self.main_doc = data

        else:
            hosts = data['nmaprun']["host"]
            for host in hosts:
                self.main_doc['nmaprun']['host'].append(host)
