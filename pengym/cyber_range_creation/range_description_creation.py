
# Import library
import sys
import os
import yaml
import subprocess

# Add pengym directory to the Python path
pengym_dir = os.path.abspath(os.path.join(os.path.dirname('pengym')))
sys.path.append(pengym_dir)

import pengym.utilities as utils
from pengym.storyboard import Storyboard
from firewall_script_creation import create_firewall_script

storyboard = Storyboard()

def check_exist_part(file_dict, part_name):
    """Check the existence of a part in a dictionary.

    Args:
        file_dict (dict): dictionary variable

        part_name (str): name of a section that needs to check

    Returns:
        (bool): True/False value
    """
    return part_name in file_dict

def create_single_program(program_path, interpreter, args=None, execute_time=None):
    """Create a single dictionary of execute program

    Args:
        program_path (str): the path of program

        interpreter (str): interpreter type

        args (optional) (str): string of arguments

        execute_time (optional) (strong): time of executing

    Returns:
        (dict): dictionary form of a single execute program
    """
    program_info = dict()

    program_info[storyboard.PROGRAM] = program_path
    if args:
        program_info[storyboard.ARGS] = args
    program_info[storyboard.INTERPRETER] = interpreter
    if execute_time:
        program_info[storyboard.EXECUTE_TIME] = execute_time

    return program_info

def generate_firewall_scripts( database,
                               range_id,
                               networks,
                               pen_scenario,
                               host_list,
                               host_data_map,
                               firewall_rule_ports,
                               firewall_rules_folder_path,
                               host_name_map):

    """Generate firewall script for all host in this scenario

    Args:
        database (dict): database that get from config file
        range_id (int): range id of network in clone settings

        networks (dict): networks information in clone settings
        that compatible with CyRIS scenario

        pen_scenario (dict): dictionary information of pengym scenario after reading yaml file
        host_list (list): list of hosts in the current network environment

        host_data_map (dict): dictionary of mapping between internal host address
        with list of available data (services and processes)

        firewall_rule_ports (list): list of pre-defined mapping between service and port
        firewall_rules_folder_path (str): directory (path) to store the firewall rule script file
        host_name_map (dict): the map between host internal address and the name (eg: (1, 0): host-1-0)
    """

    ## GENERATE FIREWALL RULE SCRIPTS IN EACH OF HOST
    pen_firewall = dict(pen_scenario[storyboard.FIREWALL])
    additional_port = database[storyboard.ADDITIONAL_PORT]
    subnet_firewall = dict()

    # Create a subnet_firewall dictionary information
    for key, services in pen_firewall.items():
        port_list = list()

        for service in services:
            port = firewall_rule_ports[service]
            port_list.append(port)

        subnet_firewall[eval(key)] = port_list

    # Create a host_firewall dictionary information
    # And generate firewall rurle scripts for each of host
    for _, host in enumerate(host_list):

        host_config = pen_scenario[storyboard.HOST_CONFIGS][str(host)]
        host_firewall_dict = dict()

        if storyboard.FIREWALL in host_config:

            host_firewall = host_config[storyboard.FIREWALL]

            for key, services in host_firewall.items():
                port_list = list()

                for service in services:
                    port = firewall_rule_ports[service]
                    port_list.append(port)

                host_firewall_dict[eval(key)] = port_list

        additional_port_list = list()
        host_data = host_data_map[host]

        for data in host_data:
            if (data in additional_port):
                additional_port_list.append(additional_port[data])

        create_firewall_script(range_id,
                                networks,
                                database[storyboard.HOST_IP],
                                host_list,
                                additional_port_list,
                                host,
                                subnet_firewall,
                                host_firewall_dict,
                                firewall_rules_folder_path,
                                host_name_map)

def create_range_description(database):
    """Create range description from PenGym scenario

    Args:
        database (dict): database that get from config file

    Returns:
        cyris_file_path (str): the directory (path) of cyris scenario yaml file
    """
    scenario_file = utils.replace_file_path(database, storyboard.SCENARIO_FILE)
    pen_scenario = utils.load_yaml_file(scenario_file)

    # MAP VALUE FROM DATABASE
    PENGYM_SOURCE = database[storyboard.PENGYM_SOURCE]
    CYRIS_DESCRIPTION_PATH = utils.replace_file_path(database, storyboard.CYRIS_DESCRIPTION_FILE)
    FIREWALL_RULES_FOLDER_PATH = utils.replace_file_path(database, storyboard.FIREWALL_RULE_PATH)
    VM_DATA_ROOT = utils.replace_file_path(database, storyboard.DST) # The root path contains copy information in VM host

    ## Host settings
    HOST_ID = database[storyboard.CYBER_RANGE][storyboard.HOST_SETTINGS][storyboard.HOST_ID]
    MGMT_ADDR = database[storyboard.CYBER_RANGE][storyboard.HOST_SETTINGS][storyboard.MGMT_ADDR]
    virbr_addr_value = database[storyboard.CYBER_RANGE][storyboard.HOST_SETTINGS][storyboard.VIRBR_ADDR]
    VIRBR_ADDR = database[virbr_addr_value]
    host_account_value = database[storyboard.CYBER_RANGE][storyboard.HOST_SETTINGS][storyboard.ACCOUNT]
    HOST_ACCOUNT = database[host_account_value]

    ## Guest_settings
    BASEVM_HOST = database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.BASEVM_HOST]

    basevm_config_file_value = database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.BASEVM_CONFIG_FILE]
    BASEVM_CONFIG_FILE = database[basevm_config_file_value]
    BASEVM_TYPE = database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.BASEVM_TYPE]
    FIREWALL_RULE_PORTS = database[storyboard.SERVICE_PORT]

    ### Tasks
    if (check_exist_part(database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS], storyboard.TASKS)):

        # Check add_account part
        if (check_exist_part(database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS], storyboard.ADD_ACCOUNT)):
            ADD_ACCOUNT = database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS][storyboard.ADD_ACCOUNT]

        # Check copy_content part
        if (check_exist_part(database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS], storyboard.COPY_CONTENT)):
            COPY_CONTENT = database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS][storyboard.COPY_CONTENT]

        # Check execute_program
        if (check_exist_part(database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS], storyboard.EXECUTE_PROGRAM)):
            EXECUTE_PROGRAM = database[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS][storyboard.EXECUTE_PROGRAM]

    ## Clone Setting
    RANGEID = database[storyboard.RANGE_ID]
    INSTANCE_NUMBER = database[storyboard.CYBER_RANGE][storyboard.CLONE_SETTINGS][storyboard.HOSTS][storyboard.INSTANCE_NUMBER]
    TOPOLOGY_TYPE = database[storyboard.CYBER_RANGE][storyboard.CLONE_SETTINGS][storyboard.HOSTS][storyboard.TOPOLOGY][storyboard.TYPE]
    INTERFACE_PREFIX = database[storyboard.CYBER_RANGE][storyboard.CLONE_SETTINGS][storyboard.HOSTS][storyboard.TOPOLOGY][storyboard.NETWORKS][storyboard.INTERFACE]

    # CYRIS SCENARIO SCRIPT CREATION

    cyris_scenario = list()

    ## HOST SETTING CREATION
    host_settings = list()
    host_settings_info = dict()

    host_settings_info[storyboard.ID] = HOST_ID
    host_settings_info[storyboard.MGMT_ADDR] = MGMT_ADDR
    host_settings_info[storyboard.VIRBR_ADDR] = VIRBR_ADDR
    host_settings_info[storyboard.ACCOUNT] = HOST_ACCOUNT

    host_settings.append(host_settings_info)

    ## GUEST SETTING CREATION
    guest = list()

    # Create list of host internal addresses from PenGym subnet information
    host_list = list()
    host_data_map = dict()
    subnets = pen_scenario[storyboard.SUBNETS]

    for sub_id, subnet in enumerate(subnets):
        for host_idx in range(subnet):
            host_list.append(tuple((sub_id + 1, host_idx)))

    # Create the map between host internal address and host name
    host_name_map = dict()
    for host_addr in host_list:
        name = f'{storyboard.HOST}-{host_addr[0]}-{host_addr[1]}'
        host_name_map[host_addr] = name

    # Create a list of guest configurations in guest_settings
    for host_addr in host_list:
        guest_info = dict()
        guest_info[storyboard.ID] = host_name_map[host_addr]
        guest_info[storyboard.BASEVM_HOST] = BASEVM_HOST
        guest_info[storyboard.BASEVM_CONFIG_FILE] = BASEVM_CONFIG_FILE
        guest_info[storyboard.BASEVM_TYPE] = BASEVM_TYPE

        # Create list of tasks for each of guest
        tasks = list()
        add_account = list()
        execute_program = list()
        copy_content = list()

        # Create a list of services and processes that are required on current guest
        host_config = pen_scenario[storyboard.HOST_CONFIGS][str(host_addr)]
        host_services = host_config[storyboard.SERVICES]
        host_processes = host_config[storyboard.PROCESSES]
        host_data = host_services + host_processes

        host_data_map[host_addr] = host_data

        # Iterate each item (service or process) in host
        for item in host_data:

            # Create list of add account tasks
            if (ADD_ACCOUNT and item in ADD_ACCOUNT):
                account_info = dict()
                account_info[storyboard.ACCOUNT] = ADD_ACCOUNT[item][storyboard.ACCOUNT]
                account_info[storyboard.PASSWD] = ADD_ACCOUNT[item][storyboard.PASSWD]

                add_account.append(account_info)

            # Create list of execute prgram tasks
            if (EXECUTE_PROGRAM and item in EXECUTE_PROGRAM):
                item_progs = EXECUTE_PROGRAM[item][storyboard.PROGRAMS]

                for program in item_progs:

                    program_info = dict()
                    program_args_str = None
                    program_exe_time = None

                    # Map program name with file
                    program_name = program[storyboard.PROGRAM]
                    program_file = utils.replace_file_path(database, program_name)
                    program_path = f"{VM_DATA_ROOT}{program_file}"

                    if storyboard.ARGS in program:

                        program_args = program[storyboard.ARGS].copy()

                        for index, program_arg in enumerate(program_args):
                            if program_arg in database[storyboard.FILE_PATH]:
                                program_args[index] = f"{VM_DATA_ROOT}{utils.replace_file_path(database, program_arg)}"

                        #Add host_id if item is proftpd
                        if (item == storyboard.PROFTPD):
                            program_args.append(host_name_map[host_addr])
                        program_args_str = " ".join(program_args)

                    if (check_exist_part(program, storyboard.EXECUTE_TIME)):
                        program_exe_time = program[storyboard.EXECUTE_TIME]

                    program_info = create_single_program (program_path = program_path,
                                                          interpreter = program[storyboard.INTERPRETER],
                                                          args = program_args_str,
                                                          execute_time = program_exe_time)

                    execute_program.append(program_info)

        # Check additional programs
        ## Check deactive cron
        if (storyboard.CRON not in host_data):
            de_cron_prgs = EXECUTE_PROGRAM[storyboard.DEACTIVE_CRON][storyboard.PROGRAMS]

            for de_cron_single_prg in de_cron_prgs:
                program_info = dict()

                program_name = de_cron_single_prg[storyboard.PROGRAM]
                program_file = utils.replace_file_path(database, program_name)

                program_info = create_single_program (program_path = f"{VM_DATA_ROOT}{program_file}",
                                                      interpreter = de_cron_single_prg[storyboard.INTERPRETER],
                                                      execute_time = de_cron_single_prg[storyboard.EXECUTE_TIME])
                
            execute_program.append(program_info)

        ## Check deactive pe_tomcat
        if (storyboard.TOMCAT not in host_data):
            de_pe_tomcat_prgs = EXECUTE_PROGRAM[storyboard.DEACTIVE_PE_TOMCAT][storyboard.PROGRAMS]

            for de_pe_tomcat_single_prg in de_pe_tomcat_prgs:
                program_info = dict()

                program_name = de_pe_tomcat_single_prg[storyboard.PROGRAM]
                program_file = utils.replace_file_path(database, program_name)

                program_info = create_single_program (program_path = f"{VM_DATA_ROOT}{program_file}",
                                                          interpreter = de_pe_tomcat_single_prg[storyboard.INTERPRETER],
                                                          execute_time = de_pe_tomcat_single_prg[storyboard.EXECUTE_TIME])

            execute_program.append(program_info)

        ## Setup firewall and check existed SSH
        firewall_rule_path = f"{VM_DATA_ROOT}{FIREWALL_RULES_FOLDER_PATH}/{host_name_map[host_addr]}_firewall.sh"
        stop_ssh_path = f"{VM_DATA_ROOT}{utils.replace_file_path(database, storyboard.STOP_SSH)}"

        if (storyboard.SSH not in host_data):
            program_args_str = f"{firewall_rule_path} {stop_ssh_path}"
        else:
            program_args_str = firewall_rule_path

        program_info = dict()
        program_file = utils.replace_file_path(database, storyboard.CONFIG_FIREWALL_STOP_SSH)

        program_info = create_single_program (program_path = f"{VM_DATA_ROOT}{program_file}",
                                                          interpreter = storyboard.BASH,
                                                          args = program_args_str,
                                                          execute_time = storyboard.AFTER_CLONE)
        execute_program.append(program_info)

        # Create copy content tasks
        if (COPY_CONTENT):
            src_value_list = COPY_CONTENT[storyboard.SRC]
            des_value = COPY_CONTENT[storyboard.DST]
            for src_value in src_value_list:

                copy_content_info = dict()
                copy_content_info[storyboard.SRC] = utils.replace_file_path(database, src_value)
                copy_content_info[storyboard.DST] = utils.replace_file_path(database, des_value)
                copy_content.append(copy_content_info)

        # Combine to into tasks section
        # Do not add the specific task if there is no item in this task
        add_account_task = dict()
        if len(add_account) > 0:
            add_account_task[storyboard.ADD_ACCOUNT] = add_account
            tasks.append(add_account_task)

        copy_content_task = dict()
        if len(copy_content) > 0:
            copy_content_task[storyboard.COPY_CONTENT] = copy_content
            tasks.append(copy_content_task)

        execute_program_task = dict()
        if len(execute_program) > 0:
            execute_program_task[storyboard.EXECUTE_PROGRAM] = execute_program
            tasks.append(execute_program_task)

        guest_info[storyboard.TASKS] = tasks

        guest.append(guest_info)

    ## CLONE SETTING CREATION
    clone_list = list()
    clone_item = dict()
    clone_host_list = list()
    clone_guest_list = list()
    clone_topology_list = list()
    clone_network_list = list()

    range_id = RANGEID
    clone_item[storyboard.RANGE_ID] = range_id

    host_info = dict()
    host_info[storyboard.HOST_ID] = HOST_ID
    host_info[storyboard.INSTANCE_NUMBER] = INSTANCE_NUMBER

    # Create list of clone guests
    for index, host_addr in enumerate(host_list):
        guest_info = dict()
        guest_info[storyboard.GUEST_ID] = host_name_map[host_addr]
        if index == 0:
            guest_info[storyboard.ENTRY_POINT] = True
        guest_info[storyboard.NUMBER] = 1

        clone_guest_list.append(guest_info)

    host_info[storyboard.GUESTS] = clone_guest_list

    # Create topology
    topology_info = dict()
    topology_info[storyboard.TYPE] = TOPOLOGY_TYPE

    # Create host interface index
    host_interfaces = dict()
    for host in host_list:
        host_interfaces[host] = 0

    pengym_topology = pen_scenario[storyboard.TOPOLOGY]

    # Create a list of networrks in topology
    for subnet_idx, subnet in enumerate(pengym_topology):
        for idx in range(subnet_idx + 1, len(subnet)):
            network_info = dict()
            member_list = list()        
            name = f'{storyboard.TOPOLOGY_PREFIX}{subnet_idx}{idx}'

            # Check connected subnets
            if subnet[idx] == 1:
                # List out all hosts within this subnet
                for host in host_list:
                    if (host[0] == subnet_idx or host[0] == idx):
                        member = f'{host_name_map[host]}.{INTERFACE_PREFIX}{host_interfaces[host]}'
                        host_interfaces[host] = host_interfaces[host] + 1
                        member_list.append(member)

                members = ', '.join(member_list)

                network_info[storyboard.NAME] = name
                network_info[storyboard.MEMBERS] = members

                clone_network_list.append(network_info)

    topology_info[storyboard.NETWORKS] = clone_network_list

    clone_topology_list.append(topology_info)
    host_info[storyboard.TOPOLOGY] = clone_topology_list

    clone_host_list.append(host_info)
    clone_item[storyboard.HOSTS] = clone_host_list

    clone_list.append(clone_item)

    # Combine to CyRIS scenario
    add_host_settings = dict()
    add_host_settings[storyboard.HOST_SETTINGS] = host_settings
    cyris_scenario.append(add_host_settings)

    add_guest_settings = dict()
    add_guest_settings[storyboard.GUEST_SETTINGS] = guest
    cyris_scenario.append(add_guest_settings)

    add_clone_settings = dict()
    add_clone_settings[storyboard.CLONE_SETTINGS] = clone_list
    cyris_scenario.append(add_clone_settings)

    ## GENERATE FIREWALL RULE SCRIPTS IN EACH OF HOST
    generate_firewall_scripts (
        database = database,
        range_id = RANGEID,
        networks = clone_network_list,
        pen_scenario = pen_scenario,
        host_list = host_list,
        host_data_map = host_data_map,
        firewall_rule_ports = FIREWALL_RULE_PORTS,
        firewall_rules_folder_path = f"/{PENGYM_SOURCE}{FIREWALL_RULES_FOLDER_PATH}",
        host_name_map = host_name_map
    )

    # Create cyris scenario yaml file
    cyris_scenario_yaml = yaml.dump(cyris_scenario, sort_keys=False)

    scenario_name = scenario_file.split('/')[-1].split('.')[0]
    cyris_file_path = f'{CYRIS_DESCRIPTION_PATH}/{scenario_name}-cyris.yaml'

    # Wrtite YAML data to a file
    with open(cyris_file_path, 'w') as file:
        file.write(cyris_scenario_yaml)

    return cyris_file_path

def create_cyber_range_workspace(database):
    """Create workspace where cyber range descriptions and neccessary files are to be instantiated

    Args:
        database (dict): database that get from config file
    """

    pengym_src = database[storyboard.PENGYM_SOURCE]
    scenario_folder = f"/{pengym_src}/{storyboard.CYBER_RANGE}/{database[storyboard.SCENARIO_NAME]}"
    firewall_folder = f"{scenario_folder}/{storyboard.FIREWALL}"

    create_scenario_folder = f"mkdir {scenario_folder}"
    create_firewall_folder = f"mkdir {firewall_folder}"

    # Execute scripts
    utils.execute_script(create_scenario_folder)
    utils.execute_script(create_firewall_folder)

# Start program
if __name__ == "__main__":

    config_file = sys.argv[-1]
    database = utils.load_yaml_file(config_file)

    # Create directories
    create_cyber_range_workspace(database)        

    # Create cyris description
    cyris_description_path = create_range_description(database)
