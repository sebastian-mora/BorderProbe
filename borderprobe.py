import ipaddress
import socket
import os

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

        except ValueError:
            print("Invalid Subnet!")


def getIP():
    """
    Gets the users IP for the report
    :return: str ip
    """

    try:
        ip = socket.gethostbyname(socket.gethostname())
        return ip

    except OSError:
        print("Unable to get Machine IP. Are you connected to the internet?")

def getProjectName():
    while True:
        dir_name = str(input("Enter a project name: "))
        if os.path.isdir('output/' + dir_name) is True:
            print("There is a project already with that name: %s" % dir_name)
        else:
            if os.path.isdir('output') is not True:
                os.mkdir('output')

            os.mkdir('output/'+ dir_name)
            return dir_name


if __name__ == '__main__':

    menu.startMenu()

    choice = menu.readInt()
    dir_name = getProjectName()

    scan = Scanner(dir_name)

    ip = getIP()

    if choice == 1:

        subnet = readSubnet()

        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        live_hosts_dic = scan.hostScan(subnet, choice)
        xml_data = scan.phaseTwoScan(live_hosts_dic)
        Report.Report(xml_data, dir_name, live_hosts_dic )

    elif choice == 2:

        filepath = input("Please Enter Path to subnet list: ")

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

        live_hosts_dic = scan.hostScan(subnets, choice)

        xml_data = scan.phaseTwoScan(live_hosts_dic)
        Report.Report(xml_data, dir_name, list(live_hosts_dic.keys()), subnets, ip)

    else:
        pass
