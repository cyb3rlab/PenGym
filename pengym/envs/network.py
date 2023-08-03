
# Import libraries
import pengym.utilities as utils
import logging
import time

from nasim.envs.network import Network
from nasim.envs.action import ActionResult
from pengym.storyboard import Storyboard

storyboard = Storyboard()

class PenGymNetwork(Network):
    """The network for a given scenario. The PenGymNetwork class is derived from the NASim Network one.

    Args:
        Network: Network Class of NASim
    """

    def perform_action(self, state, action):
        """Perform the given action against the network.

        Args:
            state (State): the current state of the network
            action (Action): the action to perform

        Returns:
            State: the state of the host after the action is performed
            ActionObservation: the result of the action
        """

        next_state, obs = super().perform_action(state, action)

        # Catch actions that did not succeed in the superclass function
        # PENGYM_ERROR is used to check if this error comes from PenGym or not; consequently we do not print a failure
        # that occured in the super function if the error has already been printed in a PenGym function
        if not obs.success and not utils.PENGYM_ERROR:
            utils.print_failure(action, obs, storyboard.TAG_NASIM_PENGYM)

        return next_state, obs

    def _perform_subnet_scan(self, next_state, action):
        """Perform subnet scan on this network. This function overrides _perform_subnet_scan() in NASim Network.

        Args:
            next_state (PenGymState): the current state of the network
            action (Action): the action to perform

        Returns:
            PenGymHostVector: the state of the host after the action is performed
            ActionObervation: the result of the action
        """

        # Set tags to differentiate between PenGym and NASim actions
        # only if both of them are enabled
        if utils.ENABLE_PENGYM and utils.ENABLE_NASIM:
            tag_pengym = storyboard.TAG_PENGYM
            tag_nasim = storyboard.TAG_NASIM
        else:
            tag_pengym = ""
            tag_nasim = ""

        utils.PENGYM_ERROR = False # Reset the value of PenGym Error

        # PenGym execution
        if utils.ENABLE_PENGYM:
            start = time.time()
            # Check if host is compromised from NAsim
            if not next_state.host_compromised(action.target):
                result = ActionResult(False, connection_error=True) # NASim code: ActionResult(False, 0.0, connection_error=True)
                utils.PENGYM_ERROR = True
                utils.print_failure(action, result, storyboard.PENGYM)

            else:

                # Map host address to IP address
                subnet_ips = utils.map_host_address_to_IP_address(utils.host_map, action.target, subnet=True)

                #Get list of available port in current network environment
                scenario_services = utils.scenario.services
                ports = utils.map_services_to_ports(scenario_services)

                # Get list of hosts in scenario
                scenario_hosts = list(utils.scenario.hosts.keys())

                # Update discovered host list
                if (action.target not in utils.host_is_discovered):
                    utils.host_is_discovered.append(action.target)

                # Do subnet scan
                subnet_scan_result = utils.host_map[action.target][storyboard.SUBNET]

                if (subnet_scan_result is None):
                    subnet_scan_result = self.do_subnet_scan(subnet_ips, utils.nmap_scanner, ports)
                    utils.host_map[action.target][storyboard.SUBNET] = subnet_scan_result

                # Map the discovered IP address to host address
                discovered_list = utils.map_IP_adress_to_host_address(utils.host_map, subnet_scan_result)
                discovered_dict = utils.map_result_list_to_dict(discovered_list, scenario_hosts, bool=True)

                end = time.time()

                # Update the state of host 
                if subnet_scan_result:
                    discovered2 = {}
                    newly_discovered2 = {}
                    discovery_reward = 0
                    target_subnet = action.target[0]

                    for h_addr in self.address_space:
                        newly_discovered2[h_addr] = False
                        discovered2[h_addr] = False

                        if self.subnets_connected(target_subnet, h_addr[0]):
                            host = next_state.get_host(h_addr)
                            discovered2[h_addr] = True

                            if not host.discovered:
                                newly_discovered2[h_addr] = True
                                host.discovered = True
                                discovery_reward += host.discovery_value

                    # Print the result
                    result = ActionResult(True, value=discovery_reward, discovered=discovered_dict,
                                          newly_discovered=self.define_newly_discovered_hosts(discovered_list))
                    print(f"  Host {action.target} Action '{action.name}' SUCCESS: discovered={result.discovered} newly_discovered={result.newly_discovered} Execution Time: {end-start:1.6f}{tag_pengym}")
                else:
                    logging.warning(f"Result of do_subnet_scan(): {subnet_scan_result}")
                    result = ActionResult(False, undefined_error=True) # connection_error may be more appropriate
                    utils.PENGYM_ERROR = True
                    utils.print_failure(action, result, storyboard.PENGYM)

                # Update host_is_discovered list
                self.update_host_is_discovered_list(discovered_list)

        # NASim execution
        # NOTE: This may not work correctly when both PenGym and NASim are active,
        # since the update state function is duplicated
        if utils.ENABLE_NASIM:
            start = time.time()
            next_state, result = super()._perform_subnet_scan(next_state, action)
            end = time.time()
            if result.success:
                print(f"  Host {action.target} Action '{action.name}' SUCCESS: discovered={result.discovered} newly_discovered={result.newly_discovered} Execution Time: {end-start:1.6f}{tag_nasim}")
            else:
                utils.print_failure(action, result, storyboard.NASIM)

        return next_state, result

    ###########################################################################################
    def do_subnet_scan(self, subnet_address, nm, ports=False):
        """Perform the subnet scan

        Args:
            subnet_address (string) : string of subnet address
            nm (PortScanner): Nmap port scanner object
            ports (list): list of ports to be scanned

        Returns:
            hosts_list (list): list of hosts in connected subnet
        """

        # -Pn: tells Nmap not to use ping to determine if the target is up
        # Nmap will do the requested scanning functions against every target IP specified, as if every one is active.
        # -n: tells Nmap not to perform DNS resolution
        # -sS: tells Nmap to use TCP SYN scanning
        # -T5: Nmap should use the most aggressive timing template
        # --min-paralell: specifies the minimum number of parallel probes to perform at once
        # --max-paralell: specifies the maximum number of parallel probes to perform at once

        TCP = 'tcp'
        STATUS = 'status'
        STATE = 'state'
        CLOSE = 'close'
        UP = 'up'
        ARGS = '-Pn -n -sS -T5 --min-parallel 100 --max-parallel 100'

        hosts_list = list()

        if ports:
            for port in ports:
                nm.scan(subnet_address, str(port), arguments=ARGS, sudo=True)

                #Get the list of active host
                for x in nm.all_hosts():
                    if nm[x][TCP][port][STATE] != CLOSE:
                       hosts_list.append(x)
        else:
            nm.scan(subnet_address, arguments=ARGS, sudo=True)
            # This work when port is not specified
            hosts_list = [x for x in nm.all_hosts() if nm[x][STATUS][STATE] == UP]

        return hosts_list

    ###########################################################################################
    def define_newly_discovered_hosts(self, discovery_host_list):
        """Define the list of newly discovered hosts from list of discovered hosts

        Args:
            discovery_host_list (list): list of host discovered via the subnet scan

        Returns:
            newly_discovered (list): list of newly discovered hosts
        """
        total_host_list = utils.host_map.keys()

        newly_discovered = dict()

        for host in total_host_list:
            newly_discovered[host] = (host not in utils.host_is_discovered) and (host in discovery_host_list)

        return newly_discovered

    ###########################################################################################
    def update_host_is_discovered_list(self, discovery_host_list):
        """Update the list of discovered host

        Args:
            discovery_host_list (list): list of hosts discovered after the subnet scan
        """
        for host in discovery_host_list:
            if host not in utils.host_is_discovered:
                utils.host_is_discovered.append(host)
