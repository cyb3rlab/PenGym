
# Import libraries
from nasim.envs import NASimEnv
from .network import PenGymNetwork
from .state import PenGymState

class PenGymEnv(NASimEnv):
    """A simulated environment for pentesting. The PenGym environment class is derived from the NASim environment one.

    Args:
        NASimEnv: Environment Class from NASim
    """

    def __init__(self, scenario, fully_obs=False, flat_actions=True, flat_obs=True):
        """Initialize the PenGym environment

        Args:
            scenario (Scenario): Scenario object, defining the properties of the environment.
            fully_obs (bool, optional): The observability mode of environment. True means fully observable mode, otherwise partially observable. Defaults to False.
            flat_actions (bool, optional): The action mode. True means a flat action space, otherwise a parameterised action space. Defaults to True.
            flat_obs (bool, optional): The observation space. True means a 1D observation space, otherwise a 2D observation space. Defaults to True.
        """

        # Call the superclass __init__ function
        super().__init__(scenario, fully_obs, flat_actions, flat_obs)

        # Initialize a PenGymNetwork object from the scenario
        self.network = PenGymNetwork(scenario)

        # Initialize the current state from the information in the network object
        self.current_state = PenGymState.generate_initial_state(self.network)
