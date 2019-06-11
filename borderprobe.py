import ipaddress

import menus as menu
from Scanner import Scanner


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


if __name__ == '__main__':
    menu.startMenu()

    choice = menu.readInt()

    if choice == 1:

        subnet = readSubnet()
        scan = Scanner(subnet)

        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        if choice == 1:
            live_hosts_file = scan.hostPingScan(subnet)
            scan.phaseTwoScan(live_hosts_file)

        elif choice == 2:
            live_hosts = scan.hostIpPing(subnet)
            scan.phaseTwoScan(live_hosts)

        elif choice == 3:
            live_hosts = scan.hostCustomScan(subnet)
            scan.phaseTwoScan(live_hosts)

        else:
            print("Invalid Input")
