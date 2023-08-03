
# Import libraries
from nasim.envs.state import State
from .host_vector import PenGymHostVector

class  PenGymState(State):
    """A State in the PenGym Environment. PenGymState is derived from NASim State.

    Args:
        State: State Class from NASim
    """
    def copy(self):
        """Copy the state content and cast it to PenGymState

        Returns:
            PenGymHostState: state of this network
        """
        state = super().copy()
        penGymState = PenGymState(state.tensor, state.host_num_map)
        return penGymState

    def get_host(self, host_addr):
        """Get host object from host address. This function overrides get_host() in NASim State.

        Args:
            host_addr (tuple): address of host

        Returns:
            PenGymHostVector: host vector corresponding to this host address
        """
        host = super().get_host(host_addr)
        penGymHost = PenGymHostVector(host.vector)
        return penGymHost
