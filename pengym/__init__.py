
# Import libraries
from nasim.scenarios import make_benchmark_scenario
from nasim.scenarios import load_scenario
from pengym.envs.environment import PenGymEnv
import pengym.utilities as utilities

# Global function for creating PenGym environments
def create_environment(scenario_name,
                       fully_obs = False,
                       flat_actions = True,
                       flat_obs = True):
    """Create a new PenGym environment

    Args:
        scenario_name (str): The name of the scenario to create an environment from.
        fully_obs (bool, optional): The observability mode of environment. True means fully observable mode, otherwise partially observable. Defaults to False.
        flat_actions (bool, optional): The action mode. True means a flat action space, otherwise a parameterised action space. Defaults to True.
        flat_obs (bool, optional): The observation space. True means a 1D observation space, otherwise a 2D observation space. Defaults to True.
    Returns:
        PenGymEnv: New PenGym environment instance
    """
    env_kwargs = {
        "fully_obs": fully_obs,
        "flat_actions": flat_actions,
        "flat_obs": flat_obs
    }

    # Create new PenGym environment instance
    utilities.scenario = make_benchmark_scenario(scenario_name)
    env = PenGymEnv(utilities.scenario, **env_kwargs)

    if env:
        print(f"  Successfully created environment using scenario '{scenario_name}'")
    else:
        print(f"  ERROR: Could not create environment using scenario '{scenario_name}'")

    return env

# Global function for loading PenGym environments from NASim scenario files
def load(path,
         fully_obs=False,
         flat_actions=True,
         flat_obs=True,
         name=None):
    """Load PenGym Environment from a NASim .yaml scenario file.

    Args:
        path (str): Path to the NASim .yaml scenario file
        fully_obs (bool, optional): The observability mode of environment. True means fully observable mode, otherwise partially observable. Defaults to False.
        flat_actions (bool, optional): The action mode. True means a flat action space, otherwise a parameterised action space. Defaults to True.
        flat_obs (bool, optional): The observation space. True means a 1D observation space, otherwise a 2D observation space. Defaults to True.
        name (str, optional): Scenario name. If None, the scenario name will be generated from the file path. Default is None.

    Returns:
        PenGymEnv: New PenGym environment object
    """
    env_kwargs = {"fully_obs": fully_obs,
                  "flat_actions": flat_actions,
                  "flat_obs": flat_obs}

    # Create new PenGym environment instance
    utilities.scenario = load_scenario(path, name)

    env = PenGymEnv(utilities.scenario, **env_kwargs)

    if env:
        print(f"  Successfully created environment using scenario '{name}'")
    else:
        print(f"  ERROR: Could not create environment using scenario '{name}'")

    return env
