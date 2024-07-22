
#############################################################################
# Run demo of PenGym functionality
#############################################################################

import time
import pengym
import numpy
import logging
import sys
import getopt
import pengym.utilities as utils
from pengym.storyboard import Storyboard

storyboard = Storyboard()

#############################################################################
# Constants
#############################################################################

# Action names/targets
SUBNET_SCAN = 'SubnetScan'
OS_SCAN = 'OSScan'
SERVICE_SCAN = 'ServiceScan'
EXPLOIT_SSH = 'Exploit_Ssh'
EXPLOIT_FTP = 'Exploit_Ftp'
EXPLOIT_SAMBA = 'Exploit_Samba'
EXPLOIT_SMTP = 'Exploit_Smtp'
EXPLOIT_HTTP = 'Exploit_Http'
PROCESS_SCAN = 'ProcessScan'
PRIVI_ESCA_TOMCAT = 'PrivilegeEscalation_Tomcat'
PRIVI_ESCA_PROFTPD = 'PrivilegeEscalation_Proftpd'
PRIVI_ESCA_CRON = 'PrivilegeEscalation_Cron'

ACTION_NAMES = {SUBNET_SCAN: "subnet_scan", OS_SCAN: "os_scan", SERVICE_SCAN: "service_scan", PROCESS_SCAN: "process_scan",
                EXPLOIT_SSH: "e_ssh",  EXPLOIT_FTP: "e_ftp", EXPLOIT_SAMBA: "e_samba", EXPLOIT_SMTP: "e_smtp", EXPLOIT_HTTP: "e_http", 
                PRIVI_ESCA_TOMCAT: "pe_tomcat", PRIVI_ESCA_PROFTPD: "pe_daclsvc", PRIVI_ESCA_CRON: "pe_schtask"}

HOST1_0 = 'host1-0'
HOST1_1 = 'host1-1'
HOST1_2 = 'host1-2'
HOST1_3 = 'host1-3'
HOST1_4 = 'host1-4'
HOST1_5 = 'host1-5'
HOST1_6 = 'host1-6'
HOST1_7 = 'host1-7'
HOST1_8 = 'host1-8'
HOST1_9 = 'host1-9'
HOST1_10 = 'host1-10'
HOST1_11 = 'host1-11'
HOST1_12 = 'host1-12'
HOST1_13 = 'host1-13'
HOST1_14 = 'host1-14'
HOST1_15 = 'host1-15'
HOST2_0 = 'host2-0'
HOST2_1 = 'host2-1'
HOST3_0 = 'host3-0'
HOST3_1 = 'host3-1'
HOST3_2 = 'host3-2'
HOST3_3 = 'host3-3'
HOST3_4 = 'host3-4'
HOST3_5 = 'host3-5'
HOST4_0 = 'host4-0'
HOST4_1 = 'host4-1'
HOST4_2 = 'host4-2'
HOST4_3 = 'host4-3'
HOST4_4 = 'host4-4'
HOST5_0 = 'host5-0'
HOST5_1 = 'host5-1'
HOST5_2 = 'host5-2'
HOST5_3 = 'host5-3'
HOST6_0 = 'host6-0'
HOST6_1 = 'host6-1'

ACTION_TARGETS = {HOST1_0: (1, 0), HOST1_1: (1, 1), HOST1_2: (1, 2), HOST1_3: (1, 3), HOST1_4: (1, 4), HOST1_5: (1, 5), HOST1_6: (1, 6), HOST1_7: (1, 7), 
                  HOST1_8: (1, 8), HOST1_9: (1, 9), HOST1_10: (1, 10), HOST1_11: (1, 11), HOST1_12: (1, 12), HOST1_13: (1, 13), HOST1_14: (1, 14), HOST1_15: (1, 15),
                  HOST2_0: (2, 0), HOST2_1: (2, 1), 
                  HOST3_0: (3, 0), HOST3_1: (3, 1), HOST3_2: (3, 3), HOST3_3: (3, 3), HOST3_4: (3, 4), HOST3_5: (3, 5), 
                  HOST4_0: (4, 0), HOST4_1: (4, 1),
                  HOST5_0: (5, 0), HOST5_1: (5, 1),
                  HOST6_0: (6, 0), HOST6_1: (6, 1)}

# Agent types
AGENT_TYPE_RANDOM = "random"
AGENT_TYPE_DETERMINISTIC = "deterministic"
DEFAULT_AGENT_TYPE = AGENT_TYPE_DETERMINISTIC

# Other constants
MAX_STEPS = 150 # Max number of pentesting steps (sys.maxsize to disable)
RENDER_OBS_STATE = False

#############################################################################
# Functions
#############################################################################

# Select an action from the action space based on its name
# 'action_name' and its target 'action_target'
def select_action(action_space, action_name, action_target):
    for i in range(0, action_space.n):
        action = action_space.get_action(i)
        if action.name == action_name and action.target == action_target:
            return action

#############################################################################
# Run pentesting with a random agent in the environment 'env'
def run_random_agent(env):

    # Initialize variables
    done = False # Indicate that execution is done
    truncated = False # Indicate that execution is truncated
    step_count = 0 # Count the number of execution steps

    # Loop while the experiment is not finished (pentesting goal not reached)
    # and not truncated (aborted because of exceeding maximum number of steps)
    while not done and not truncated:

        # Sample a random action from the action space of this environment
        action = env.action_space.sample()

        # Increment step count and execute action
        step_count = step_count + 1
        print(f"- Step {step_count}: {env.action_space.get_action(action)}")
        observation, reward, done, truncated, info = env.step(action)
        if RENDER_OBS_STATE:
            env.render() # render most recent observation
            env.render_state() # render most recent state

        # Conditional exit (for debugging purposes)
        if step_count >= MAX_STEPS:
            logging.warning(f"Abort execution after {step_count} steps")
            break

    return done, truncated, step_count

#############################################################################
# Run pentesting with a deterministic agent in the environment 'env'
def run_deterministic_agent(env, deterministic_path):

    # Initialize variables
    done = False # Indicate that execution is done
    truncated = False # Indicate that execution is truncated
    step_count = 0 # Count the number of execution steps

    # Loop while the experiment is not finished (pentesting goal not reached)
    # and not truncated (aborted because of exceeding maximum number of steps)
    while not done and not truncated:
        # Exit if there are no more steps in the deterministic path
        if step_count >= len(deterministic_path):
            break

        # Retrieve the next action to be executed
        action_tuple = deterministic_path[step_count]
        action = select_action(env.action_space, ACTION_NAMES[action_tuple[1]], ACTION_TARGETS[action_tuple[0]])

        # Increment step count and execute action
        step_count = step_count + 1
        
        print(f"- Step {step_count}: {action}")
          
        observation, reward, done, truncated, info = env.step(action)

        if RENDER_OBS_STATE:
            env.render() # render most recent observation
            env.render_state() # render most recent state

        # Conditional exit (for debugging purposes)
        if step_count >= MAX_STEPS:
            logging.warning(f"Abort execution after {step_count} steps")
            break

    return done, truncated, step_count

# Create PenGym environment using scenario 'scenario_name'
def create_pengym_environment(scenario_name):
    env = pengym.create_environment(scenario_name)

    # Initialize seed for numpy (used to determine exploit success/failure) and
    # for the environment action space (used to determine order of random actions)
    seed = 1 # NORMAL: No e_ssh failure during pentesting path
    #seed = 300 # INCOMPLETE: Cause e_ssh failure during pentesting path
    numpy.random.seed(seed)
    env.action_space.seed(1)

    return env

# Create PenGym environment using custom scenario
def create_pengym_custom_environment(scenario_path):
    env = pengym.load(scenario_path)

    seed = 1
    numpy.random.seed(seed)
    env.action_space.seed(1)

    return env

# Print usage information
def usage():
    print("\nOVERVIEW: Run demo of the PenGym training framework for pentesting agents\n")
    print("USAGE: python3 run.py [options] <CONFIG_FILE> \n")
    print("OPTIONS:")
    print("-h, --help                     Display this help message and exit")
    print("-a, --agent_type <AGENT_TYPE>  Agent type (random/deterministic)")
    print("-d, --disable_pengym           Disable PenGym execution in cyber range")
    print("-n, --nasim_simulation         Enable NASim simulation execution")

#############################################################################
# Main program
#############################################################################
def main(args):

    # Configure logging
    logging.basicConfig(level=logging.INFO,
                        format='* %(levelname)s: %(filename)s: %(message)s')


    print("#########################################################################")
    print("PenGym: Pentesting Training Framework for Reinforcement Learning Agents")
    print("#########################################################################")

    # Default argument values
    agent_type = DEFAULT_AGENT_TYPE
    config_path = None

    # Parse command line arguments
    try:
        # Make sure to add ':' for short-form and '=' for long-form options that require an argument
        opts, trailing_args = getopt.getopt(args, "ha:dn",
                                            ["help", "agent_type=", "disable_pengym", "nasim_simulation"])
    except getopt.GetoptError as err:
        logging.error(f"Command-line argument error: {str(err)}")
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-a", "--agent"):
            agent_type = arg
        elif opt in ("-d", "--disable_pengym"):
            utils.ENABLE_PENGYM = False
        elif opt in ("-n", "--nasim_simulation"):
            utils.ENABLE_NASIM = True
        else:
            # Nothing to do, since unrecognized options are caught by
            # the getopt.GetoptError exception above
            pass

    # Get path of configuration file
    try:
        config_path = trailing_args[0]
    except Exception as e:
        logging.error(f"Configuration file is not specified")
        usage()
        sys.exit(2)

    # Print parameters
    print(f"* Execution parameters:")
    print(f"  - Agent type: {agent_type}")
    print(f"  - PenGym cyber range execution enabled: {utils.ENABLE_PENGYM}")
    print(f"  - NASim simulation execution enabled: {utils.ENABLE_NASIM}")

    # Check execution parameters
    if not (utils.ENABLE_PENGYM or utils.ENABLE_NASIM):
        logging.error("Either PenGym or NASim must be enabled")
        usage()
        sys.exit(2)

    print(f"* Read configuration from '{config_path}'...")
    utils.init_config_info(config_path)

    # Create an experiment environment using scenario path
    scenario_path = utils.replace_file_path(utils.config_info, storyboard.SCENARIO_FILE)
    print(f"* Create environment using custom scenario from '{scenario_path}'...")
    env = create_pengym_custom_environment(scenario_path)

    if utils.ENABLE_PENGYM:
        print(f"* Read configuration from '{config_path}'...")
        utils.init_config_info(config_path)
        
        print("* Initialize MSF RPC client...")
        utils.init_msfrpc_client()
        
        print("* Initialize Nmap Scanner...")
        utils.init_nmap_scanner()
        
        # Create host map dictionary
        range_detail_file = utils.replace_file_path(database=utils.config_info,
                                                     file_name=storyboard.RANGE_DETAILS_FILE)

        utils.init_host_map(range_details_file=range_detail_file)

        # Initializer map of service ports
        utils.init_service_port_map()
    
        # Deactivate bridge that not conneccted to Internet
        utils.init_bridge_setup(range_details_file=range_detail_file)

    # Run experiment using a random agent
    if agent_type == AGENT_TYPE_RANDOM:
        print("* Perform pentesting using a RANDOM agent...")
        done, truncated, step_count = run_random_agent(env)

    # Run experiment using a deterministic agent
    elif agent_type == AGENT_TYPE_DETERMINISTIC:

        # Set up deterministic path

        # Optimal path for scenario "medium-single-site" according to "medium-single-site.yaml" note
        deterministic_path = [ (HOST5_1, EXPLOIT_HTTP), (HOST5_1, SUBNET_SCAN),
                        (HOST2_1, EXPLOIT_SMTP), (HOST2_1, SUBNET_SCAN),
                        (HOST3_1, EXPLOIT_HTTP),
                        (HOST3_4, EXPLOIT_SSH), (HOST3_4, PRIVI_ESCA_TOMCAT)]

        # Pentesting path for scenario "tiny" assuming need for service/process discovery
        deterministic_path = [ (HOST5_1, OS_SCAN), (HOST5_1, SERVICE_SCAN), (HOST5_1, EXPLOIT_HTTP), (HOST5_1, SUBNET_SCAN),
                (HOST2_1, OS_SCAN), (HOST2_1, SERVICE_SCAN), (HOST2_1, EXPLOIT_SMTP), (HOST2_1, SUBNET_SCAN),
                (HOST3_1, OS_SCAN), (HOST3_1, SERVICE_SCAN), (HOST3_1, EXPLOIT_HTTP),
                (HOST3_4, OS_SCAN), (HOST3_4, SERVICE_SCAN), (HOST3_4, EXPLOIT_SSH), (HOST3_4, PROCESS_SCAN), (HOST3_4, PRIVI_ESCA_TOMCAT)]

        print("* Execute pentesting using a DETERMINISTIC agent...")
        done, truncated, step_count = run_deterministic_agent(env, deterministic_path)

    else:
        logging.error(f"Unrecognized agent type: '{agent_type}'")
        usage()
        sys.exit(1)

    # Print execution status
    if done:
        # All the goals in the scenario file were reached
        print(f"* NORMAL execution: {step_count} steps")
    elif truncated:
        # Execution was truncated before reaching all the goals (for random agents, etc.)
        print(f"* TRUNCATED execution: {step_count} steps")
    else:
        # Execution finished before reaching all the goals (for deterministic agents)
        print(f"* INCOMPLETE execution: {step_count} steps")

    if utils.ENABLE_PENGYM:
        print("* Clean up MSF RPC client...")
        utils.cleanup_msfrpc_client()

        print("* Restore the to intial state of the firewalls for all hosts...")
        utils.save_restore_firewall_rules_all_hosts(flag=storyboard.RESTORE)

#############################################################################
# Run program
if __name__ == "__main__":
    start = time.time()
    main(sys.argv[1:])
    end = time.time()
    print(f"Execution Time: {end-start:1.6f}s")
