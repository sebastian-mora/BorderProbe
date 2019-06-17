import ipaddress
import socket

from helpers import menus as menu, Report
from helpers.Scanner import Scanner


def readSubnet():
    """
    Takes user subnet and validates
    :return [IPv4network]
    """

    while 1:
        input_str = input("Enter Subnet (XXX:XXX:XXX:XXX/ZZ): ")

        try:
            subnet = ipaddress.ip_network(input_str, strict=False)
            return [subnet]

        except IOError:
            print("Invalid Subnet!")


def getIP():
    """
    Gets the users IP for the report
    :return: str ip
    """

    try:
        ip = socket.gethostbyname(socket.gethostname())
        return ip

    except IOError:
        print("Unable to get Machine IP. Are you connected to the internet?")


if __name__ == '__main__':

    menu.startMenu()

    choice = menu.readInt()
    scan = Scanner()

    ip = getIP()

    if choice == 1:

        subnet = readSubnet()

        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        host_dic = scan.hostScan(subnet, choice)
        xml_data = scan.phaseTwoScan(host_dic)
        Report.Report(xml_data, subnet, ip)

    elif choice == 2:

        filepath = input("Please Enter Path to file: ")

        try:
            with open(filepath)as fd:
                subnets = [line.rstrip('\n') for line in fd]
            fd.close()

        except FileNotFoundError:
            print("File Not Found")
            exit(1)

        subnets = [ipaddress.ip_network(subnet, strict=False) for subnet in subnets]

        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        live_hosts_file = scan.hostScan(subnets, choice)

        xml_data = scan.phaseTwoScan(live_hosts_file)
        Report.Report(xml_data, subnets, ip)

    else:
        pass
