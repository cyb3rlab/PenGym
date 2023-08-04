
# Import libraries
import numpy as np
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

# Default values regarding default PenGym/NASim execution
ENABLE_PENGYM = True
PENGYM_ERROR = False
ENABLE_NASIM = False

# Define the maping of host internal address (ids) to IP addresses and other host related info.
# Currently, the IP addresses are initialized with values suitable for the 'tiny' network scenario,
# but this structure will be automatically created in the future.
host_map = {
    (1,0): {
        'host_ip' : ['34.1.1.2', '34.1.2.2', '34.1.3.2'],
        'subnet_ip': '34.1.1.0/24 34.1.2.0/24 34.1.3.0/24 34.1.4.0/24',
        'bridge_up': False,
        'shell': None,
        'meterpreter': None,
        'os': None,
        'services': None,
        'processes': None,
        'subnet': None,
        'access': 0.0  # 0 is None
    },
    (2,0): {
        'host_ip' : ['34.1.2.3', '34.1.4.2'],
        'subnet_ip': '34.1.1.0/24 34.1.2.0/24 34.1.3.0/24 34.1.4.0/24',
        'bridge_up': False,
        'shell': None,
        'meterpreter': None,
        'os': None,
        'services': None,
        'processes': None,
        'subnet': None,
        'access': 0.0  # 0 is None
    },
    (3,0): {
        'host_ip' : ['34.1.3.3', '34.1.4.3'],
        'subnet_ip' : '34.1.1.0/24 34.1.2.0/24 34.1.3.0/24 34.1.4.0/24',
        'bridge_up': False,
        'shell': None,
        'meterpreter': None,
        'os': None,
        'services': None,
        'processes': None,
        'subnet': None,
        'access': 0.0  # 0 is None
    }
}

# Define the mapping of CyRIS subnets to the corresponding bridge names
# Currently, the bridge names are initialized with values suitable for the 'tiny' network scenario,
# but this structure will be automatically created in the future.
bridge_map = {
    'link01': 'br34-1-1',
    'link12': 'br34-1-2',
    'link13': 'br34-1-3',
    'link23': 'br34-1-4'
}

def init_config_info(config_path):
    """Parse the config file into config information

    Args:
        config_path (str): directory of config file
    """
    try:
        global config_info
        with open(config_path, 'r') as file:
            config_info = yaml.load(file, Loader=yaml.FullLoader)
    except Exception as e:
        print(f"* ERROR: Failed to load the configuration file: {e}", file=sys.stderr)
        sys.exit(2)

def init_msfrpc_client():
    """Initialize the Metasploit client
    """
    # Initialize variables from configuration
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
        for job_id, _ in msfrpc_client.jobs.list.items():
            msfrpc_client.jobs.stop(job_id)
        for session_key, session_details in msfrpc_client.sessions.list.items():
            msfrpc_client.sessions.session(session_key).stop()

def init_nmap_scanner():
    """Initialize the nmap scanner for scanning actions
    """
    try:
        global nmap_scanner
        nmap_scanner = nmap.PortScanner()
    except Exception as e:
        print(f"* WARNING: Failed to initialize NMap: {e}", file=sys.stderr)
        sys.exit(2)

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
            value_dict[value] = np.float32(value in resultValues)

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
        host_map (dictionary): A mapping value of IP adresses, subnet IP addresses and shell object of each host in the scenario
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
        host_map (dictionary): A mapping value of IP adresses, subnet IP addresses and shell object of each host in the scenario
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

def print_failure(action, observation, context):
    """Print out the error types of actions on current host
       There are 3 kinds of error: connection error, permission error and undefined error

    Args:
        action (Action): The current action is executed 
        observation (ActionResult): The result information of the action
        context (string): pengym/nasim
    """
    print(f"  Host {action.target} Action '{action.name}' FAILURE:"
                  f"{' connection_error=TRUE' if observation.connection_error else ''}"
                  f"{' permission_error=TRUE' if observation.permission_error else ''}"
                  f"{' undefined_error=TRUE'  if observation.undefined_error  else ''} [{context}]")

def activate_bridge(bridge_name):
    """Activate the bridge

    Args:
        bridge_name (string): The name of bridge that need to activate
    """
    command = f"sudo ifconfig {bridge_name} up"

    # Execute the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Check the return code
    if result.returncode == 0:
        pass
    else:
        print("Error: ", result.stderr)

def deactivate_bridge(bridge_name):
    """De-activate the bridge

    Args:
        bridge_name (string): The name of bridge that need to de-activated 
    """
    command = f"sudo ifconfig {bridge_name} down"

    # Execute the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Check the return code
    if result.returncode == 0:
        pass
    else:
        print(f"  Error: ", result.stderr)

def init_bridge_setup():
    """Create bridge map, init the setup of bridges
        De-activate hosts that are not connected to the Internet
    """

    conntected_subnet = list()
    internet = scenario.topology[0]

    for idx in range(1, len(internet)):
        if internet[idx] == 1:
            subnet_name = f'link0{idx}'
            conntected_subnet.append(subnet_name)

    # Deactivate bridge of hosts that are not connected to the Internet
    for link in bridge_map.keys():
        if link not in subnet_name:
            bridge_name = bridge_map[link]
            deactivate_bridge(bridge_name)

def activate_host_bridge(host):
    """Activate all the bridges of host when it is compromised
    """
    prefix_link = f"{host[0]}"

    for link in bridge_map.keys():
        if prefix_link in link:
            bridge_name = bridge_map[link]
            activate_bridge(bridge_name)

def init_service_port_map():
    """Create the service port map
    """
    global service_port_map 
    service_port_map = config_info[storyboard.SERVICE_PORT]

def map_services_to_ports(services):
    """Mapping list of services to list of corresponding ports
    Args:
        services (list): list of services

    Returns:
        ports (list): list of corresponding ports
    """
    port_list = list()

    for service in services:
        port = service_port_map[service]
        port_list.append(port)

    return port_list
