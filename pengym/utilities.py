
# Import libraries
import numpy as np
import psutil
from pymetasploit3.msfrpc import MsfRpcClient
from pengym.storyboard import Storyboard

import sys
import nmap
import subprocess
import yaml

# Declare global variables
global config_info
global scenario
global host_map
global bridge_map
global service_port_map
global host_is_discovered
global msfrpc_client
global nmap_scanner
global current_state
global ENABLE_PENGYM
global ENABLE_NASIM
global PENGYM_ERROR

# Declare constant values from pengym board
storyboard = Storyboard()

# Declare discovered host list
host_is_discovered = list()

# Declare Metasploit and Nmap objects
msfrpc_client = None
nmap_scanner = None
service_port_map = None
current_state = None

# Default values regarding default PenGym/NASim execution
ENABLE_PENGYM = True
PENGYM_ERROR = False
ENABLE_NASIM = False

def load_yaml_file(file_path):
    """Load YAML file to dictionary
    
    Args:
        file_pathh (str): directory of yaml file
    """
    try:
        with open(file_path, 'r') as file:
            return yaml.load(file, Loader=yaml.FullLoader)
    except Exception as e:
        print(f"* ERROR: Failed to load the {file_path} file: {e}", file=sys.stderr)
        sys.exit(2)

def execute_script(command):
    """Execute the shell command script
        
        Args:
            command (str): shell command
        """

    # Execute the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Check the return code
    if result.returncode == 0:
        pass
    else:
        print("Error: ", result.stderr)

def init_config_info(config_path):
    """Parse the config file into config information

    Args:
        config_path (str): directory of config file
    """
    global config_info
    config_info = load_yaml_file(config_path)

def init_msfrpc_client():
    """Initialize the Metasploit client
    """
    my_password = config_info[storyboard.MSFRPC_CONFIG][storyboard.MSFRPC_CLINET_PWD] 
    port = config_info[storyboard.MSFRPC_CONFIG][storyboard.MSFRPC_PORT] 
    ssl = config_info[storyboard.MSFRPC_CONFIG][storyboard.SSL]

    try:
        global msfrpc_client
        msfrpc_client = MsfRpcClient(my_password, port=port, ssl=ssl)
    except Exception as e:
        print(f"* ERROR: Failed to connect to MSF RPC client: {e}", file=sys.stderr)
        sys.exit(2)

def cleanup_msfrpc_client():
    """Clean up the Metasploit client, and close sessions after the agent finishes running 
    """
    global msfrpc_client

    if msfrpc_client:
        while (len(msfrpc_client.jobs.list) != 0 or len(msfrpc_client.sessions.list) !=0):
            for job_id, _ in msfrpc_client.jobs.list.items():
                msfrpc_client.jobs.stop(job_id)
            for session_key, session_details in msfrpc_client.sessions.list.items():
                try:
                    msfrpc_client.sessions.session(session_key).stop()
                except Exception as e:
                    print(f"* WARRNING: Failed to stop session {session_key}: {e}")

def init_nmap_scanner():
    """Initialize the nmap scanner for scanning actions
    """
    try:
        global nmap_scanner
        nmap_scanner = nmap.PortScanner()
    except Exception as e:
        print(f"* WARNING: Failed to initialize NMap: {e}", file=sys.stderr)
        sys.exit(2)

def extract_network_info(range_details_file):
    """Extract network informatiion from the cyber range detail yaml file

    Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS

    Returns:
        network(dict): network information dictionary
    """
    
    yaml_dict = load_yaml_file(range_details_file)
    network = list()

    # Get the list of instances
    instance_list = yaml_dict[storyboard.HOSTS][0][storyboard.INSTANCES]

    for instance in instance_list:

        instance_dict = dict()
        subnet_list = list()
        host_list = list()

        
        instance_dict[storyboard.INSTANCE] = instance[storyboard.INSTANCE_INDEX]
        
        for guest in instance[storyboard.GUESTS]:
            
            host = dict()
            host_ip = list()
            host_subnet = list()
            
            host[storyboard.NAME] = guest[storyboard.GUEST_ID]
            host[storyboard.KVM_DOMAIN] = guest[storyboard.KVM_DOMAIN]
            
            # Get the ip and subnet address of each host
            for _, value in guest[storyboard.IP_ADDRESSES].items():
                host_ip.append(value)
                subnet = value[:-1] + "0/24"
                if subnet not in host_subnet:
                    host_subnet.append(subnet)
                    if subnet not in subnet_list:
                        subnet_list.append(subnet)
            
            for _, value in guest[storyboard.GATEWAYS].items():
                host[storyboard.GATEWAYS] = value
            
            host[storyboard.SUBNET] = host_subnet
            host[storyboard.HOST_IP] = host_ip
            host_list.append(host)
        
        instance_dict[storyboard.SUBNET_INSTANCE] = subnet_list
        instance_dict[storyboard.HOSTS] = host_list
        
        network.append(instance_dict)

    return network

def create_host_map(range_details_file, instance_index):
    """Create host_map dictionary to map NASim host address 
    to PenGym host address and information. 
    
    Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS
        
        instance_index (int): instance number of network in clone setting 
        that compatible with CyRIS scenario

    Returns:
        map: host_map dictionary
    """
    map = dict()
    subnet = dict()
    network = extract_network_info(range_details_file)

    for instance in network:
        if instance[storyboard.INSTANCE] == instance_index:
            hosts = instance[storyboard.HOSTS]
            break

    for host in hosts:
        map_info = dict()
        subnet_id = host[storyboard.NAME].split('-')[1]
        subnet_ip = ' '.join(host[storyboard.SUBNET])

        # Get the index of host in the subnet
        if subnet_id in subnet:
            host_id = subnet[subnet_id] + 1
        else:
            host_id = 0

        subnet[subnet_id] = host_id
        
        map_info[storyboard.HOST_IP] = host[storyboard.HOST_IP] # List of IP of this host
        map_info[storyboard.SUBNET_IP] = subnet_ip # All subnet addresses of this network
        map_info[storyboard.KVM_DOMAIN] = host[storyboard.KVM_DOMAIN]
        map_info[storyboard.BRIDGE_UP] = False # Flag to turn on/off the bridge
        map_info[storyboard.SHELL] = None # Shell object after obtaining the shell
        map_info[storyboard.OS] = None # OS value after executing OS Scan
        map_info[storyboard.SERVICES] = None # Services value after executing service scan
        map_info[storyboard.PROCESSES] = None # Process value after executing process scan
        map_info[storyboard.SUBNET] = None # Subnet value after executing subnet scan
        map_info[storyboard.PE_SHELL] = dict() # Root shell object after obtaining the shell
        map_info[storyboard.EXPLOIT_ACCESS] = dict() # Access value of exploit action
        map_info[storyboard.ACCESS] = 0.0 # Access level of current host
        map_info[storyboard.DEFAULT_GW] = None # Status of default gateway in current VM
        map_info[storyboard.SERVICE_SCAN_STATE] = True # State of service scan
        map_info[storyboard.OS_SCAN_STATE] = True # State of OS Scan
        map_info[storyboard.SERVICE_EXPLOIT_STATE] = True # State of sevice exploit action

        key = (int(subnet_id),host_id)
        map[key] = map_info

    return map

def create_bridge_map(range_details_file, instance_index):
    """Create bridge_map dictionary to map NASim subnet link to name of bridge. 
    
    Args:
        network_path (str): path of folder contains range detail 
        information yaml file after creating by CyRIS

        instance_index (int): instance number of network in clone setting 
        that compatible with CyRIS scenario

    Returns:
        bridge_map: bridge_map dictionary
    """
    
    yaml_dict = load_yaml_file(range_details_file)
    
    bridge_map = dict()
    brige_info = list
    bridge_info = None
    
    # Get the instance of the cyber range
    for instance in yaml_dict[storyboard.HOSTS][0][storyboard.INSTANCES]:
        if instance[storyboard.INSTANCE_INDEX] == instance_index:
            guest_list = instance[storyboard.GUESTS]
            break
    
    for guest in guest_list:
        
        ip_address = guest[storyboard.IP_ADDRESSES]
        networks = dict(guest[storyboard.NETWORKS])
        
        # Map bridge name to corresponding network link
        for key, link in networks.items():
            if link not in bridge_map:
                if bridge_info is None:
                    bridge_idx = '-'.join(ip_address[key].split('.')[:-1])
                    bridge_name = f"br{bridge_idx}"
                else:
                    bridge_name = bridge_info[link]
                bridge_ip = ip_address[key][:-1] + "1"
                brige_info = [bridge_name, bridge_ip, False]
                bridge_map[link] = brige_info
    
    return bridge_map

def init_host_map(range_details_file, instance_index = 1):
    """Initialize the host map global variable

    Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS
        
        instance_index (int, optional): instance number of network in clone setting 
        that compatible with CyRIS scenario (Default = 1)
    """
    try:
        global host_map
        host_map = create_host_map(range_details_file, instance_index)
    except Exception as e:
        print(f"* WARNING: Failed to create host map: {e}", file=sys.stderr)

def reset_host_map():
    """Reset the neccessary attribute of host map
    """
    global host_map

    for address in host_map.keys():
        host_map[address][storyboard.BRIDGE_UP] = False
        host_map[address][storyboard.SHELL] = None
        host_map[address][storyboard.OS] = None
        host_map[address][storyboard.SERVICES] = None
        host_map[address][storyboard.PROCESSES] = None
        host_map[address][storyboard.SUBNET] = None
        host_map[address][storyboard.PE_SHELL] = dict()
        host_map[address][storyboard.EXPLOIT_ACCESS] = dict()
        host_map[address][storyboard.ACCESS] = 0.0
        host_map[address][storyboard.DEFAULT_GW] = None
        host_map[address][storyboard.SERVICE_SCAN_STATE] = True
        host_map[address][storyboard.OS_SCAN_STATE] = True
        host_map[address][storyboard.SERVICE_EXPLOIT_STATE] = True

def init_bridge_setup(range_details_file, instance_index = 1):
    """Create bridge map, init the setup of bridges
        De-activate hosts that are not connected to the Internet
        
        Args:
        range_details_file (str): path of cyber range detail 
        information yaml file after creating by CyRIS
        
        instance_index (int, optional): instance number of network in clone setting 
        that compatible with CyRIS scenario (Default = 1)
    """
    try:
        global bridge_map
        bridge_map = create_bridge_map(range_details_file, instance_index)
    except Exception as e:
        print(f"* WARNING: Failed to create bridge map: {e}", file=sys.stderr)

    conntected_subnet = list()
    internet = scenario.topology[0]

    for idx in range(1, len(internet)):
        if internet[idx] == 1:
            subnet_name = f'link0{idx}'
            conntected_subnet.append(subnet_name)

    # Deactivate bridge of hosts that are not connected to the Internet
    for link in bridge_map.keys():
        if link not in conntected_subnet:
            bridge_name = bridge_map[link][0]
            print(f"  Deactivate bridge {bridge_name}...")
            deactivate_bridge(bridge_name)

def init_service_port_map():
    """Create the service port map
    """
    global service_port_map 
    service_port_map = config_info[storyboard.SERVICE_PORT]

def map_result_list_to_dict(resultValues, scenarioValues, bool=False):
    """Transform the result values from PenGym format (list) to NASim format (dictionary of all values in scenario with True/False)
    Example: PenGym format ['ssh']
    -> NASim format {'ssh': 1.0, 'tcp': 0.0}, where 1.0 means True, 0.0 means False (Default)
       OR
    -> NASim format {'ssh': True, 'tcp': False}, in case the bool flag is on

    Args:
        resultValues (list): List of result values from PenGym actions
        scenarioValues (list): List of all values from scenario (list of all processes/os/services from scenario)
        bool (bool, optional): True/False value flag. Defaults to False

    Returns:
        value_dict(dict): Dictionary format of resultValues
    """
    value_dict = dict()

    for value in scenarioValues:
        if bool:
            value_dict[value] = value in resultValues
        else:
            value_dict[value] = value_dict[value] = np.float32(any(value in service for service in resultValues))

    return value_dict

def map_dict_values_to_list(dictValues):
    """Transform the dictionary values to list 
    Example: 
    {'ssh': True, 'ftp': False}
    -> ['ssh']

    Args:
        dictValues (dict): Dictionary of values
        scenarioValues (list): List of all values from scenario (list of all processes/os/services from scenario)
        bool (bool, optional): True/False value flag. Defaults to False

    Returns:
        value_dict(dict): Dictionary format of resultValues
    """
    value_list = list()

    for value, status in dictValues.items():
        if status:
           value_list.append(value)

    return value_list

def map_host_address_to_IP_address(host_map, host, subnet = False):
    """Mapping host key address of NASim host to a list of IP addresses of corresponding PenGym host
    A list of subnet IP addresses of the PenGym host is returned if the subnet flag is on

    Args:
        host_map (dict): A mapping value of IP adresses, subnet IP addresses and shell object of each host in the scenario
        host (tuple): Host key address of NASim host
        subnet (bool, optional): Subnet flag
        True if want to return list of subnet IP addresses. Defaults to False

    Returns:
        (list): List of subnet ip addresses or host IP addresses of corresponding host
    """
    if subnet:
        return host_map[host][storyboard.SUBNET_IP]
    else:
        return host_map[host][storyboard.HOST_IP]

def map_IP_adress_to_host_address(host_map, ip_list):
    """Mapping list of IP addresses of PenGym hosts to each host key address of corresponding NASim hosts

    Args:
        host_map (dict): A mapping value of IP adresses, subnet IP addresses and shell object of each host in the scenario
        ip_list (list): List of IP addresses of PenGym hosts

    Returns:
        (list): list of corresponding host key address of NASim hosts
    """
    host_address_list = list()

    for ip in ip_list:
        for key, value in host_map.items():
            if ip in value[storyboard.HOST_IP]:
                if (not key in host_address_list): # Check to avoid duplicate host key value. 
                    host_address_list.append(key)

    return host_address_list

def print_failure(action, observation, context, exec_time):
    """Print out the error types of actions on current host
       There are 3 kinds of error: connection error, permission error and undefined error

    Args:
        action (Action): The current action is executed 
        observation (ActionResult): The result information of the action
        context (str): pengym/nasim
        exec_time (double): Execution time
    """
    print(f"  Host {action.target} Action '{action.name}' FAILURE:"
                  f"{' connection_error=TRUE' if observation.connection_error else ''}"
                  f"{' permission_error=TRUE' if observation.permission_error else ''}"
                  f"{' undefined_error=TRUE'  if observation.undefined_error  else ''}"
                  f" Execution Time: {exec_time:1.6f}[{context}]")

def check_bridge_status (bridge_name):
    """Check the status of the bridge (on/off)

    Args:
        bridge_name (str): The name of bridge that need to activate
    
    Return:
        (bool): True if bridge is up
    """
    for iface, details in psutil.net_if_stats().items():
        if (iface == bridge_name):
            return details.isup

def activate_bridge(bridge_name):
    """Activate the bridge

    Args:
        bridge_name (str): The name of bridge that need to activate
    """
    command = f"sudo ifconfig {bridge_name} up"

    execute_script(command)

def deactivate_bridge(bridge_name):
    """De-activate the bridge

    Args:
        bridge_name (str): The name of bridge that need to de-activated 
    """
    command = f"sudo ifconfig {bridge_name} down"
    
    # Execute script
    execute_script(command)

def activate_host_bridge(host):
    """Activate all the bridges of host when it is compromised
    
    Args:
        host (tuple): Current host address (e.g. (1,0))
    
    Returns:
        activate_link_list (list): List of activate link (key in bridge_map, e.g., link01)
    """
    prefix_link = f"{host[0]}"
    activate_link_list = []

    for link in bridge_map.keys():
        if prefix_link in link:
            bridge_name = bridge_map[link][0]
            bridge_state = bridge_map[link][2]
            if not bridge_state:
                activate_bridge(bridge_name)
                bridge_map[link][2] = True
                activate_link_list.append(link)

    return activate_link_list

def check_host_compromised_within_subnet(subnet_id):
    """Check if there is any host be compromised in the current subnet

    Args:
        subnet_id (int): subnet index
    """
    for host_id, host_item in host_map.items():
        if host_id[0] == subnet_id:
            if host_item[storyboard.SHELL] is not None:
                return True
    
    return False

def update_host_service_scan_state(current_subnet, has_host_compromised, activate_link_list):
    """Update the service scan state of hosts that need to reexecute the service scan.
        When a host within a subnet becomes compromised, 
        the state of the hosts within this subnet and the connected subnets changes.
        
        Args:
            current_subnet (str): Current subnet of the current host
            has_host_compromised (bool): Check value if there is any host has been compromised in currrent subnet
            activate_link_list (list): List of activated link after current host be compromised
    """
    update_flag = False
    for link in activate_link_list:

        for host_idx, _ in host_map.items():
            subnet_id = host_idx[0]
            
            if str(subnet_id) in link:
                if (subnet_id == current_subnet) and (not has_host_compromised):
                        update_flag = True
                elif (subnet_id != current_subnet) and (not check_host_compromised_within_subnet(subnet_id)):
                        update_flag = True

            if update_flag:
                host_map[host_idx][storyboard.SERVICE_SCAN_STATE] = True
                host_map[host_idx][storyboard.SERVICE_EXPLOIT_STATE] = True
                host_map[host_idx][storyboard.OS_SCAN_STATE] = True
                update_flag = False # reset the flag after updating

def save_restore_firewall_rules (script_path, vm_name, flag):
    """Save/Restore firewall rule of a single host

    Args:
        script_path (str): address of add firewall rule script
        vm_name (str): name of virtual machine
        flag (str): save or restore option
    """
    
    command = f"expect {script_path} {vm_name} {flag}"

    # Execute script
    execute_script(command)

def save_restore_firewall_rules_all_hosts (flag):
    """Save/Restore firewall rule of all hosts

    Args:
        vm_name (str): name of virtual machine
        network_id (id): the index of cyberrange
        flag (str): save or restore option
    """

    script_path = 'pengym/envs/scripts/save_restore_firewall_rule.exp'
    
    hosts = list(scenario.hosts.keys())

    for host in hosts:
        vm_name = host_map[host][storyboard.KVM_DOMAIN]
        save_restore_firewall_rules(script_path, vm_name, flag)

def add_firewall_rules (script_path, vm_name, bridge_IP):
    """Add firewall rule to allow traffic from bridge point to a host

    Args:
        script_path (str): address of add firewall rule script
        vm_name (str): name of virtual machine
        bridge_IP (str): the IP address of bridge point
    """
    
    command = f"expect {script_path} {vm_name} {bridge_IP}"

    execute_script(command)

def add_firewall_rules_all_hosts (subnet_id):
    """Add firewall rules to allow traffic from bridge point to whole hosts in a subnet 
    when one of host within subnet is compromised

    Args:
        subnet_id (int): subnet index
    """

    script_path = 'pengym/envs/scripts/add_firewall_rule.exp'
    
    hosts = list(scenario.hosts.keys())

    for host in hosts:
        if host[0] == subnet_id:
            vm_name = host_map[host][storyboard.KVM_DOMAIN]

            for link, bridge_info in bridge_map.items():
                if str(subnet_id) in link:
                    bridge_ip = bridge_info[1]
                    add_firewall_rules(script_path, vm_name, bridge_ip)

def open_firewall_rule_e_samba(host):
    """Open the firewall of current host for executing samba-based exploit action
    It is used as a temporary solution because of an unknown port that the Metasploit module uses to execute actions using the samba service

    Args:
        host (tuple): Current host address
    """
    script_path = 'pengym/envs/scripts/open_firewall_rule.exp'
    
    vm_name = host_map[host][storyboard.KVM_DOMAIN]
    add_firewall_rules(script_path, vm_name, None)

def update_default_gw (target_host, bridge_ip):
    """Update the active default gw of a host

    Args:
        target_host (tuple): host need to update gw
        bridge_ip (str): ip address of bridge that is active
    """

    script_path = 'pengym/envs/scripts/del_add_default_gw.exp'
    vm_name = host_map[target_host][storyboard.KVM_DOMAIN]
    
    command = f'expect {script_path} {vm_name} {bridge_ip}'

    # Execute script
    execute_script(command)
    
def check_and_update_available_gw (target_host):
    """Check if the current default gw of the currennt host is active or not; 
    Update the default gw of the current host to active address 
    It is used to check the pre condition of exploit action

    Args:
        target_host (tuple): host need to update gw
    """
    subnet = target_host[0]
    
    # Get list of connected bridge to this host
    for link, bridge_info in bridge_map.items():
        if str(subnet) in link:
            bridge_name = bridge_info[0]
            if check_bridge_status(bridge_name):
                update_default_gw(target_host, bridge_info[1])
                host_map[target_host][storyboard.DEFAULT_GW] = True
                break

def map_services_to_ports(services, subnet=False):
    """Mapping list of services to list of corresponding ports
    Args:
        services (list): list of services
        subnet (bool, optional): Subnet flag
        True if want to return list of subnet IP addresses. Defaults to False

    Returns:
        port_list (list): list of corresponding ports
    """
    port_list = list()

    for service in services:
        if (subnet):
            port = service_port_map[service]
            port_list.append(port)
        else:
            if services[service] == True:
                port = service_port_map[service]
                port_list.append(port)
    
    return port_list

def replace_file_path(database, file_name):
    """Replace the file name by corresponding path that pre-defined in config file
    
    Args:
        database (dict): database that get from config file
        file_name (str): name of file

    Returns:
        (str): file path that is replaced scenario value and pengym_source value
    """
    return database[storyboard.FILE_PATH][file_name]\
            .replace(storyboard.SCENARIO_NAME_PATTERN, database[storyboard.SCENARIO_NAME])\
            .replace(storyboard.PENGYM_SOURCE_PATTERN, database[storyboard.PENGYM_SOURCE])\
            .replace(storyboard.CYRIS_SOURCE_PATTERN, database[storyboard.CYRIS_SOURCE])\
            .replace(storyboard.RANGE_ID_PATTERN, str(database[storyboard.RANGE_ID]))\
            .replace(storyboard.CYBER_RANGE_DIR_PATTERN, database[storyboard.CYBER_RANGE_DIR])