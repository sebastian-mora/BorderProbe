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


def divideSubnet(ipv4_subnet):
    """
    Divides subnet into /x where x is x=x+4
    :param ipv4_subnet:
    :return: list[Pv4sNetworks]
    """

    return list(ipv4_subnet.subnets(prefixlen_diff=4, new_prefix=None))



if __name__ == '__main__':
    menu.startMenu()

    choice = menu.readInt()


    if choice == 1:

        subnet = readSubnet()
        scan = Scanner(divideSubnet(subnet))

        menu.hostDiscoveryMethods()
        choice = menu.readInt()

        if choice == 1:
            scan.pingOnlyScan()

        elif choice == 2:
            scan.hostComboScan()

        else:
            print("Invalid INput")
