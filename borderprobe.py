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
            return subnet

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

    if choice == 1:

        subnet = readSubnet()
        scan = Scanner(subnet)

        subnet_str = str(subnet)
        ip = getIP()
        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        if choice == 1:
            live_hosts_file = scan.hostPingScan(subnet)
            xml_data = scan.phaseTwoScan(live_hosts_file)
            Report.Report(xml_data, subnet_str, ip)

        elif choice == 2:
            live_hosts = scan.hostIpPing(subnet)
            xml_data = scan.phaseTwoScan(live_hosts)
            Report.Report(xml_data, subnet_str, ip)

        elif choice == 3:
            live_hosts = scan.hostCustomScan(subnet)
            xml_data = scan.phaseTwoScan(live_hosts)
            Report.Report(xml_data, subnet_str, ip)

        else:
            print("Invalid Input")

    elif choice == 2:
        pass


    else:
        print("Invalid Input")
