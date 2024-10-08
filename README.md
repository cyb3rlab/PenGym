
# PenGym: Pentesting Training Framework for Reinforcement Learning Agents

PenGym is a framework for creating and managing realistic environments
used for the training of **Reinforcement Learning** (RL) agents for
penetration testing purposes. PenGym uses the same API with the
[Gymnasium](https://github.com/Farama-Foundation/Gymnasium) fork of
the OpenAI **Gym** library, thus making it possible to employ PenGym
with all the RL agents that follow those specifications. PenGym is
being developed by [Japan Advanced Institute of Science and
Technology](https://www.jaist.ac.jp/english/) (JAIST) in collaboration
with [KDDI Research, Inc.](https://www.kddi-research.jp/english)

_**NOTE:** PenGym was created and is intended only for research
activities. You should only use PenGym in your own local network
environment and at your own risk. Any other kind of use, in particular
with network environments that do not belong to you, may be considered
an attack and lead to your legal liability. PenGym implements several
penetration testing actions that may affect target hosts, namely
network scanning via nmap, and exploit and privilege escalation via
Metasploit. Consequently, PenGym should always be used with due care
in real network environments._

An overview of PenGym is shown in the figure below. The core component
is the **Action/State Module**, which: (i) converts the actions
generated by the RL agent into real actions that are executed in a
**Cyber Range** (an actual network environment used for cybersecurity
training purposes); (ii) interprets the outcome of the actions and
returns the state of the environment and the reward to the agent, so
that processing can continue. Another important component is the
module in charge of creating the cyber range, which is the [Cyber
Range Instantiation System](https://github.com/crond-jaist/cyris)
(**CyRIS**) previously developed at JAIST. CyRIS uses the descriptions
in the **RangeDB** database to create cyber ranges that were
specifically designed for RL agent training. Currently, PenGym has 
integrated CyRIS to automate the cyber range creation process.

<div align=center><img src='figures/pengym_overview.png'></div>


## Prerequisites

PenGym has several prerequisites that must be installed before using
it, as it will be explained next:

1. **NASim**: The Action/State module implementation in PenGym is
   based on extending the functionality of the [Network Attack
   Simulator](https://github.com/Jjschwartz/NetworkAttackSimulator)
   (NASim).  You can install NASim from the PyPi Python package index
   via the `pip3` command, which will also install all its
   dependencies, such as `gymnasium` itself:

   ```
   $ sudo pip3 install nasim
   ```

   Depending on your system, you may also need to install the
   `tkinter` Python3 interface to Tcl/Tk:

   ```
   sudo apt install python3-tk
   ```

2. **CyRIS**: In order to create cyber ranges, the cyber range
   instantiation system CyRIS is recommended. Follow the instructions
   on the [CyRIS page](https://github.com/crond-jaist/cyris) for this
   purpose. Alternatively, cyber ranges could also be created by any
   other means you are familiar with, but then you need to configure
   them yourself. Note that for the current version of PenGym, the
   operating system of VMs in the cyber range should be Ubuntu 20.04
   LTS. When using CyRIS, such VMs can be created by following the
   CyRIS User Guide, in particular the Appendix "Guest VM Base Image
   Preparation".

   Additionally, the services, process packages need to be prepared 
   in advance inside `database/resources` directory as desribed below:

   | Service/process | Required packages |
   | --- | --- |
   | `ftp` | vsftpd-2.3.4 |
   | `proftpd` | proftpd-1.3.3 |
   | `samba` | samba-4.5.9 |
   | `smtp` | opensmtpd-6.6.1p1 |
   | `http` | httpd-2.4.49 |

4. **Nmap**: The Action/State module implementation uses `nmap` for
   actions such as port and network scanning. To install `nmap` and
   the corresponding Python module `python-nmap` run the following:

   ```
   sudo apt install nmap
   sudo pip3 install python-nmap
   ```

5. **Metasploit**: The Action/State module implementation uses the
   Metasploit framework for actions such as Exploit. To install
   Metasploit follow the instructions on the corresponding [Metasploit
   page](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/).
   Then also install the corresponding Python module `pymetasploit3`:

   ```
   sudo pip3 install pymetasploit3
   ```

   Once Metasploit is installed, you should start the RPC daemon by
   running the command below (if you change the password or the MSF
   RPC client port, you will also need to update the file
   `pengym/CONFIG.yml`):

   ```
   msfrpcd -P my_password
   ```

## Setup

Once the prerequisite installation is complete, to set up the most
recent version of PenGym you need to obtain its source code, either
from the most recent release or by using the `git clone` command. Then
you should update the following files to ensure that they match your
installation:

1. `pengym/CONFIG.yml`, in which global PenGym settings are configured. 
The configure and path information should be updated based on your own paths,
as described below:

   | Parameter | Description |
   | --- | --- |
   | `pengym_source` | The location of PenGym folder |
   | `cyber_range_dir` | The location where the cyber range is to be instantiated in CyRIS (it must be the same as the path in CyRIS CONFIG) |
   | `host_mgmt_addr` | The IP of main server on which the cyber range is running (localhost) |
   | `host_virbr_addr` | The IP address of the main server where the cyber range is created |
   | `host_account` | The account of the main server used to host the VMs in KVM |
   | `guest_basevm_config_file` | The location of the base VM image used to create cyber range guest VMs |
   | `scenario_name` | The name of the scenario that is used for conducting the pentesting path (we used `medium-multi-site` scenario for demonstration) |
   
   Another configure information such as ports and `msfrpc_config` can be updated based on your actual setting.

2. `run.py`, which is used to run the pentesting execution in PenGym. 
In this demo, we use the deterministic path of the `medium-multi-site` scenario 
for executing pentesting. This path should be updated based on the current situation.

## Quick Start

In order to see PenGym in action, you must first create the cyber
range, then run the included demo script. The example cyber range is
created automatically based on the `medium-multi-site` scenario.

The example agent is currently a deterministic agent that can reach the scenario goals
in 16 steps; its implementation and default action sequence are included in the file `run.py`.

The three commands that must be run are as follows (we assume you are
located in the PenGym directory):

1. Run the `range_description_creation.py` file to create the CyRIS description.
    Then, it is used to create the cyber range via CyRIS. The description file will be located in the `cyber_range/<scenario_name>` directory.

    ```
    python3 ./pengym/cyber_range_creation/range_description_creation.py ./pengym/CONFIG.yml 
    ```

2. Run CyRIS by providing the path to the directory where it is
   installed to create a cyber range:

   ```
   <CYRIS_PATH>/main/cyris.py <CYRIS_DESCRIPTION_PATH> <CYRIS_PATH>/CONFIG
   ```

3. Run the PenGym demo script with the configuration file as argument:

   ```
   python3 run.py ./pengym/CONFIG.yml
   ```

   **NOTE:** You can use the option `-h` to find out more about the
   command-line arguments of the demo script. For example, enabling
   the NASIM simulation mode and disabling cyber range execution
   (options `-n -d`) may be useful if you want to quickly test an
   agent without creating a cyber range.

   The output of PenGym should be similar to that shown below.

   ```
   #########################################################################
   PenGym: Pentesting Training Framework for Reinforcement Learning Agents
   #########################################################################
   * Execution parameters:
   - Agent type: deterministic
   - PenGym cyber range execution enabled: True
   - NASim simulation execution enabled: False
   * Create environment using custom scenario from './pengym/scenarios/medium-multi-site-pengym.yaml'...
   * Read configuration from './pengym/CONFIG.yml'...
   * Initialize MSF RPC client...
   * Initialize Nmap Scanner...
   * Execute pentesting using a DETERMINISTIC agent...
   - Step 1: OSScan: target=(5, 1), cost=1.00, prob=1.00, req_access=USER
     Host (5, 1) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 5.531204
   - Step 2: ServiceScan: target=(5, 1), cost=1.00, prob=1.00, req_access=USER
     Host (5, 1) Action 'service_scan' SUCCESS: services={'ssh': 0.0, 'ftp': 0.0, 'http': 1.0, 'samba': 0.0, 'smtp': 0.0} Execution Time: 1.950998
   - Step 3: Exploit: target=(5, 1), cost=2.00, prob=1.00, req_access=USER, os=None, service=http, access=1
     Host (5, 1) Action 'e_http' SUCCESS: access=USER services={'ssh': 0.0, 'ftp': 0.0, 'http': 1.0, 'samba': 0.0, 'smtp': 0.0} os={'linux': 1.0} Execution Time: 6.973643
   - Step 4: SubnetScan: target=(5, 1), cost=1.00, prob=1.00, req_access=USER
     Host (5, 1) Action 'subnet_scan' SUCCESS: discovered={(1, 0): False, (1, 1): False, (2, 0): True, (2, 1): True, (3, 0): False, (3, 1): False, (3, 2): False, (3, 3): False, (3, 4): False, (3, 5): False, (4, 0): False, (4, 1): False, (5, 0): True, (5, 1): True, (6, 0): False, (6, 1): False} newly_discovered={(1, 0): False, (1, 1): False, (2, 0): True, (2, 1): True, (3, 0): False, (3, 1): False, (3, 2): False, (3, 3): False, (3, 4): False, (3, 5): False, (4, 0): False, (4, 1): False, (5, 0): True, (5, 1): False, (6, 0): False, (6, 1): False} Execution Time: 6.284184
   - Step 5: OSScan: target=(2, 1), cost=1.00, prob=1.00, req_access=USER
     Host (2, 1) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 4.580497
   - Step 6: ServiceScan: target=(2, 1), cost=1.00, prob=1.00, req_access=USER
     Host (2, 1) Action 'service_scan' SUCCESS: services={'ssh': 0.0, 'ftp': 0.0, 'http': 0.0, 'samba': 0.0, 'smtp': 1.0} Execution Time: 0.943482
   - Step 7: Exploit: target=(2, 1), cost=3.00, prob=1.00, req_access=USER, os=linux, service=smtp, access=2
     Host (2, 1) Action 'e_smtp' SUCCESS: access=ROOT services={'ssh': 0.0, 'ftp': 0.0, 'http': 0.0, 'samba': 0.0, 'smtp': 1.0} os={'linux': 1.0} Execution Time: 6.661961
   - Step 8: SubnetScan: target=(2, 1), cost=1.00, prob=1.00, req_access=USER
     Host (2, 1) Action 'subnet_scan' SUCCESS: discovered={(1, 0): True, (1, 1): True, (2, 0): True, (2, 1): True, (3, 0): True, (3, 1): True, (3, 2): True, (3, 3): True, (3, 4): True, (3, 5): True, (4, 0): True, (4, 1): True, (5, 0): True, (5, 1): True, (6, 0): True, (6, 1): True} newly_discovered={(1, 0): True, (1, 1): True, (2, 0): False, (2, 1): False, (3, 0): True, (3, 1): True, (3, 2): True, (3, 3): True, (3, 4): True, (3, 5): True, (4, 0): True, (4, 1): True, (5, 0): False, (5, 1): False, (6, 0): True, (6, 1): True} Execution Time: 15.060795
   - Step 9: OSScan: target=(3, 1), cost=1.00, prob=1.00, req_access=USER
     Host (3, 1) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 5.693840
   - Step 10: ServiceScan: target=(3, 1), cost=1.00, prob=1.00, req_access=USER
     Host (3, 1) Action 'service_scan' SUCCESS: services={'ssh': 0.0, 'ftp': 0.0, 'http': 1.0, 'samba': 0.0, 'smtp': 0.0} Execution Time: 7.743670
   - Step 11: Exploit: target=(3, 1), cost=2.00, prob=1.00, req_access=USER, os=None, service=http, access=1
     Host (3, 1) Action 'e_http' SUCCESS: access=USER services={'ssh': 0.0, 'ftp': 0.0, 'http': 1.0, 'samba': 0.0, 'smtp': 0.0} os={'linux': 1.0} Execution Time: 6.689062
   - Step 12: OSScan: target=(3, 4), cost=1.00, prob=1.00, req_access=USER
     Host (3, 4) Action 'os_scan' SUCCESS: os={'linux': 1.0} Execution Time: 3.704905
   - Step 13: ServiceScan: target=(3, 4), cost=1.00, prob=1.00, req_access=USER
     Host (3, 4) Action 'service_scan' SUCCESS: services={'ssh': 1.0, 'ftp': 0.0, 'http': 0.0, 'samba': 0.0, 'smtp': 0.0} Execution Time: 0.595288
   - Step 14: Exploit: target=(3, 4), cost=3.00, prob=1.00, req_access=USER, os=linux, service=ssh, access=1
     Host (3, 4) Action 'e_ssh' SUCCESS: access=USER services={'ssh': 1.0, 'ftp': 0.0, 'http': 0.0, 'samba': 0.0, 'smtp': 0.0} os={'linux': 1.0} Execution Time: 1.365891
   - Step 15: ProcessScan: target=(3, 4), cost=1.00, prob=1.00, req_access=USER
     Host (3, 4) Action 'process_scan' SUCCESS: processes={'tomcat': 1.0, 'proftpd': 0.0, 'cron': 0.0} access=USER Execution Time: 1.024053
   - Step 16: PrivilegeEscalation: target=(3, 4), cost=1.00, prob=1.00, req_access=USER, os=linux, process=tomcat, access=2
     Host (3, 4) Action 'pe_tomcat' SUCCESS: access=ROOT processes={'tomcat': 1.0, 'proftpd': 0.0, 'cron': 0.0} os={'linux': 1.0} Execution Time: 17.723360
   * NORMAL execution: 16 steps
   * Clean up MSF RPC client...
   ```
## References

For a research background about PenGym, please consult the following
paper:

* Huynh Phuong Thanh Nguyen, Kento Hasegawa, Kazuhide Fukushima, Razvan Beuran, "PenGym: Realistic training environment for reinforcement learning pentesting agents",
Computers & Security, Volume 148, 2025, 104140, ISSN 0167-4048. ([open access](https://doi.org/10.1016/j.cose.2024.104140))

* Nguyen, T., Chen, Z., Hasegawa, K., Fukushima, K. and Beuran, R.
  "PenGym: Pentesting Training Framework for Reinforcement Learning Agents",
  10th International Conference on Information Systems Security and Privacy (ICISSP 2024), vol. 1, 2024, pp. 498-509.
