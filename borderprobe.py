import ipaddress
import socket

from helpers import menus as menu, Report
from helpers.Scanner import Scanner


def readSubnet():
    """
    Takes user subnet and validates
    :return IPv4Network
    """

    while 1:
        subnet = input("Enter Subnet (XXX:XXX:XXX:XXX/ZZ): ")

        try:

            subnet = ipaddress.ip_network(subnet, strict=False)
            return [subnet]

        except:
            print("Invalid Subnet!")


def getIP():
    try:
        ip = socket.gethostbyname(socket.gethostname())
        return ip

    except:
        print("Unable to get Machine IP. Are you connected to the internet?")


if __name__ == '__main__':
    menu.startMenu()

    choice = menu.readInt()
    scan = Scanner()

    ip = getIP()

    if choice == 1:

        subnet = readSubnet()
        subnet_str = [str(subnet)]

        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        host_dic = scan.hostScan(subnet, choice)
        xml_data = scan.phaseTwoScan(host_dic)
        Report.Report(xml_data, subnet_str, ip)

    elif choice == 2:

        filepath = input("Please Enter Path to file")

        with open(filepath)as fd:
            subnets = [line.rstrip('\n') for line in fd]

        subnets = [ipaddress.ip_network(subnet, strict=False) for subnet in subnets]

        # TODO add scan types
        live_hosts_file = scan.hostScan(subnets, 1)

        #  TODO make phaseTwoScan return list of xml files
        xml_data = scan.phaseTwoScan(live_hosts_file)
        Report.Report(xml_data, subnets, ip)



else:
    print("Invalid Input")
