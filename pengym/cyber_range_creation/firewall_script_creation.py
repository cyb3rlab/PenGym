
# Import library
import sys
import os
import subprocess

# Add pengym directoryy to the Python path
pengym_dir = os.path.abspath(os.path.join(os.path.dirname('pengym')))
sys.path.append(pengym_dir)

from pengym.storyboard import Storyboard

storyboard = Storyboard()

def create_subnets_map(rangeid, networks):
    """Create the subnets-map to map subnet name to corresponding subnet IPs 
    (e.g. {'link01': '1.1.1.0/24'})

    Args:
        range_id (int): range id of network in clone settings
        that compatible with CyRIS scenario

        networks (dict): networks information in clone settings
        that compatible with CyRIS description
        (e.g. {'name': 'link01'; 'member': 'host-1-0.eth0', 'host-1-1.eth0'})

    Returns:
        subnet_map (dict): subnets-map dictionary between link name and link network between two subnets
    """ 
    subnet_map = dict()
    for idx, network in enumerate(networks):
        subnet = f"{rangeid}.1.{idx+1}.0/24"
        subnet_map[network[storyboard.NAME]] = subnet

    return subnet_map

def map_ip_address(subnets_map, networks):
    """Create a ip address map to map interfaces of each host with corresponding ip addresses

    Args:
        subnets_map (dict): subnets-map dictionary between
        link name and link network between two subnets

        networks (dict): networks information in clone settings
        that compatible with CyRIS description

    Returns:
        host_addr_map (dict): ip address map between interfaces of each host with corresponding ip address
    """ 
    host_addr_map = dict()
    for network in networks:
        subnet_part = subnets_map[network[storyboard.NAME]].split('.0')[0]
        host_interface_list = network[storyboard.MEMBERS].split(', ')

        for idx, host_interface in enumerate(host_interface_list):
            host_addr_map[host_interface] = f"{subnet_part}.{idx+2}"

    return host_addr_map

def host_interface_two_hosts(host1, host2, networks):
    """Create a dictionary to map internal host addresses with
    corresponding host interfaces that use to connect two hosts together

    Args:
        host1 (tuple): host internal address (eg. (1,0))
        host2 (tuple): host internal address (eg. (1,0))

        networks (dict): networks information in clone settings
        that compatible with CyRIS scenario

    Returns:
        host_interfaces (dict): map between internal host addresses and
        corresponding host interfaces that use to connect two hosts together
    """ 
    host_interfaces = dict()

    host1_name = f"{storyboard.HOST}-{host1[0]}-{host1[1]}"
    host2_name = f"{storyboard.HOST}-{host2[0]}-{host2[1]}"

    for network in networks:
        if (str(host1[0]) in network[storyboard.NAME] and str(host2[0]) in network[storyboard.NAME]):
            members_list = network[storyboard.MEMBERS].split(', ')

            for member in members_list:
                if host1_name in member:
                    host_interfaces[host1] = member
                if host2_name in member:
                    host_interfaces[host2] = member

    return host_interfaces

def set_default_rule():
    """Create a list of default firewall rules

    Returns:
        default_rules (list): list of default firewall rules
    """
    default_rules = list()

    default_rules.append(storyboard.NET_IPV4_FWD)
    default_rules.append(storyboard.CLEAR_FIREWALL)
    default_rules.append(storyboard.DROP_INPUT)

    return default_rules

def accept_host_rule(host_ip):
    """Create a rule for accepting transaction from the main host(DevHost)

    Args:
        host_ip (str): ip address of main host (DevHost)

    Returns:
        (str): a rule for accepting transaction from the main host(DevHost)
    """
    return f"iptables -A INPUT -s {host_ip} -j ACCEPT"

def accept_inside_rule(subnet, port):
    """Create a rule for accepting transaction
    from a subnet to current host and match the port

    Args:
        subnet (str): subnet address
        port (int): port number that allows for transaction

    Returns:
        (str): a rule for accepting transaction
        from a subnet to specific host and match the port
    """
    return f"iptables -A INPUT -s {subnet} -p tcp -m tcp --dport {port} -j ACCEPT"

def accept_outside_rules(subnet, port):
    """Create a rule for accepting transaction
    from current host to subnet and match the port

    Args:
        subnet (str): subnet address
        port (int): port number that allows for transaction

    Returns:
        (str): a rule for accepting transaction
        from current host to subnet and match the port
    """
    return f"iptables -A INPUT -s {subnet} -p tcp -m tcp --sport {port} -j ACCEPT"

def accept_additional_rules(port_list):
    """Create a rule for accepting additional transaction
    from current host to subnet and match the port
    (used for supporting execute metasploit modules)

    Args:
        port_list (int): list of ports that allows for additional transaction

    Returns:
        (list): list of rules that accept the transaction
        of addional ports to the current host
    """
    rules = list()

    for port in port_list:
        rule_str = f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT"
        rules.append(rule_str)

    return rules

def drop_individual_rule(host_ip, port):
    """Create a rule for rejecting transaction from a host to the current host
    and mach the port

    Args:
        host_ip (str): ip address of rejecting host
        port (int): port number that allows for transaction

    Returns:
        (str): a rule for rejecting transaction
        from a host to the current host
    """
    return f"iptables -A INPUT -s {host_ip} -p tcp -m tcp --dport {port} -j DROP"

def drop_rules(target_host, host_list, subnets_map, networks, host_firewall):
    """Create a list of rejected rules from the denied host to the current host
    that pre-defined in host_configuration in PenGym scenario and mach the services

    Args:
        target_host (str): ip address of target host (current host)
        host_list (list): list of hosts in the current network environment

        subnets_map (dict): subnets-map dictionary between
        link name and link network between two subnets

        networks (dict): networks information in clone settings
        that compatible with CyRIS scenario

        host_firewall (dict): firewall rules of the current host that define
        which hosts and services are denied to the current host

    Returns:
        drop_rules (list): a list of rejected rules from the denied host to the current host
    """
    drop_rules = list()
    ip_addr_map = map_ip_address(subnets_map, networks)

    for host in host_list:
        if host in host_firewall:
            host_interface = host_interface_two_hosts(target_host, host, networks)

            host_addr = ip_addr_map[host_interface[host]]
            port_list = host_firewall[host]

            for port in port_list:
                rule = drop_individual_rule(host_addr, port)
                drop_rules.append(rule)

    return drop_rules

def accept_rules(target_host, subnet_firewall, subnets_map):
    """Create a list of accepted rules from the subnets to the current host
    that pre-defined in firewall part in PenGym scenario and mach the service

    Args:
        target_host (str): ip address of target host (current host)

        subnet_firewall (dict): firewall rules between each of subnet
        in the current network environment

        subnets_map (dict): subnets-map dictionary between
        link name and link network between two subnets

    Returns:
        accept_rules (list): a list of accepted rules from the
        pre-defined subnets to the current host
    """
    accept_rules = list()
    host_subnet = target_host[0]

    for key, port_list in subnet_firewall.items():

        if host_subnet == key[0]:

            for link, subnet_addr in subnets_map.items():
                if (str(key[0]) in link and str(key[1]) in link):

                    for port in port_list:
                        accept_rule = accept_outside_rules(subnet_addr, port)
                        accept_rules.append(accept_rule)

        if host_subnet == key[1]:

            for link, subnet_addr in subnets_map.items():
                if (str(key[0]) in link and str(key[1]) in link):

                    for port in port_list:
                        accept_rule = accept_inside_rule(subnet_addr, port)
                        accept_rules.append(accept_rule)

    return accept_rules

def create_firewall_script(rangeid,
                           networks,
                           host_ip,
                           host_list,
                           additional_port_list,
                           target_host,
                           subnet_firewall,
                           host_firewall,
                           firewall_rules_folder_path,
                           host_name_map):

    """Create firewall script for the current host

    Args:
        range_id (int): range id of network in clone settings

        networks (dict): networks information in clone settings
        that compatible with CyRIS scenario

        host_ip (str): ip address of main host (DevHost)
        host_list (list): list of hosts in the current network environment

        additional_port_list (list): list of ports that allows for additional transaction
        (used for supporting execute metasploit modules)

        target_host (str): ip address of target host (current host)

        subnet_firewall (dict): firewall rules between each of subnet
        in the current network environment

        host_firewall (dict): firewall rules of the current host that define
        which hosts and services are denied to the current host

        host_name_map (dict): the map between host internal address
        and the name (eg: (1, 0): host-1-0)

        firewall_rules_folder_path (str): directory (path) to store the firewall rule script file

    Returns:
        file_name (str): name of the firewall rule script file
        file_path (str): directory (path) of the firewall rule script file
    """
    rule_lists = list()

    subnets_map = create_subnets_map(rangeid, networks)

    rule_lists.append(set_default_rule())
    rule_lists.append(accept_host_rule(host_ip))

    if host_firewall is not None:
        rule_lists.append(drop_rules(target_host, host_list, subnets_map, networks, host_firewall))

    rule_lists.append(accept_rules(target_host, subnet_firewall, subnets_map))
    rule_lists.append(accept_additional_rules(additional_port_list))

    rule_lists.append(storyboard.SAVE_FIREWALL)

    # Combine all the rules list and single rule string into one list
    final_rule_list = [item for sublist in rule_lists for item in (sublist if isinstance(sublist, list) else [sublist])]

    # Write into bash script and make this file executable
    file_name = f"{host_name_map[target_host]}_firewall.sh"
    file_path = f"{firewall_rules_folder_path}/{file_name}"

    with open(file_path, 'w') as file:
        for rule in final_rule_list:
            file.write(f"{rule}\n")

    subprocess.call(['chmod', '+x', file_path])

    return file_name, file_path
