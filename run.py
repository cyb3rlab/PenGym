
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


#############################################################################
# Constants
#############################################################################

# Action names/targets
SUBNET_SCAN = 'SubnetScan'
OS_SCAN = 'OSScan'
SERVICE_SCAN = 'ServiceScan'
EXPLOIT_SSH = 'Exploit_Ssh'
PROCESS_SCAN = 'ProcessScan'
PRIVI_ESCA_TOMCAT = 'PrivilegeEscalation_Tomcat'

ACTION_NAMES = {SUBNET_SCAN: "subnet_scan", OS_SCAN: "os_scan", SERVICE_SCAN: "service_scan",
                EXPLOIT_SSH: "e_ssh",  PROCESS_SCAN: "process_scan", PRIVI_ESCA_TOMCAT: "pe_tomcat"}

HOST1 = 'host1'
HOST2 = 'host2'
HOST3 = 'host3'

ACTION_TARGETS = {HOST1: (1, 0), HOST2: (2, 0), HOST3: (3, 0)}

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

    if utils.ENABLE_PENGYM:
        print(f"* Read configuration from '{config_path}'...")
        utils.init_config_info(config_path)
        
        print("* Initialize MSF RPC client...")
        utils.init_msfrpc_client()
        
        print("* Initialize Nmap Scanner...")
        utils.init_nmap_scanner()
        
        utils.init_service_port_map()
        
    # Create an experiment environment
    scenario_name = "tiny"
    print(f"* Create environment using scenario '{scenario_name}'...")
    env = create_pengym_environment(scenario_name)
    
    # Deactivate bridge that not conneccted to Internet
    utils.init_bridge_setup()

    # Run experiment using a random agent
    if agent_type == AGENT_TYPE_RANDOM:
        print("* Perform pentesting using a RANDOM agent...")
        done, truncated, step_count = run_random_agent(env)

    # Run experiment using a deterministic agent
    elif agent_type == AGENT_TYPE_DETERMINISTIC:

        # Set up deterministic path

        # Optimal path for scenario "tiny" according to "tiny.yaml" note
        # deterministic_path = [ ("host1", "Exploit_Ssh"), ("host1", "SubnetScan"),
        #                 ("host3", "Exploit_Ssh"), ("host3", "PrivilegeEscalation_Tomcat"),
        #                 ("host2", "Exploit_Ssh"), ("host2", "PrivilegeEscalation_Tomcat") ]

        # Pentesting path for scenario "tiny" assuming need for service/process discovery
        deterministic_path = [ (HOST1, OS_SCAN), (HOST1, SERVICE_SCAN), (HOST1, EXPLOIT_SSH), (HOST1, SUBNET_SCAN),
                 (HOST3, OS_SCAN), (HOST3, SERVICE_SCAN), (HOST3, EXPLOIT_SSH), (HOST3, PROCESS_SCAN), (HOST3, PRIVI_ESCA_TOMCAT),
                 (HOST2, OS_SCAN), (HOST2, SERVICE_SCAN), (HOST2, EXPLOIT_SSH), (HOST2, PROCESS_SCAN), (HOST2, PRIVI_ESCA_TOMCAT) ]

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

#############################################################################
# Run program
if __name__ == "__main__":
    start = time.time()
    main(sys.argv[1:])
    end = time.time()
    #print(f"Execution Time: {end-start:1.6f}s")
