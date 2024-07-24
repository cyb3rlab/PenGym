
# Store various constant values used by PenGym
class Storyboard():
    # Constant values for getting config information
    CYBER_RANGE = 'cyber_range'
    HOST = 'host'
    INTERFACE = 'interface'
    NETWORK_SETTINGS = 'network_settings'
    TOPOLOGY_PREFIX = 'link'
    SERVICE_PORT = 'service_port'
    ADDITIONAL_PORT = 'additional_port'
    DATABASE = 'database'
    SCENARIO_NAME = 'scenario_name'
    SCENARIO_NAME_PATTERN = '{scenario_name}'
    PENGYM_SOURCE = 'pengym_source'
    PENGYM_SOURCE_PATTERN = '{pengym_source}'
    CYRIS_SOURCE = 'cyris_source'
    CYRIS_SOURCE_PATTERN = '{cyris_source}'
    RANGE_ID_PATTERN = '{range_id}'
    CYBER_RANGE_DIR = 'cyber_range_dir'
    CYBER_RANGE_DIR_PATTERN = '{cyber_range_dir}'
    RANGE_DETAILS_FILE = 'range_details_file'

    # Constant values for msfrpc client
    MSFRPC_CONFIG = 'msfrpc_config'
    MSFRPC_CLINET_PWD = 'msfrpc_client_pwd'
    MSFRPC_PORT = 'port'
    SSL = 'ssl'

    # Constant values for creating host map and bridge map
    HOST_IP = 'host_ip'
    SUBNET_IP = 'subnet_ip'
    KVM_DOMAIN = 'kvm_domain'
    BRIDGE_UP = 'bridge_up'
    SHELL = 'shell'
    OS = 'os'
    SERVICES = 'services'
    PROCESSES = 'processes'
    NETWORKS = 'networks'
    EXPLOIT_ACCESS = 'exploit_access'
    PE_SHELL = 'pe_shell'
    ACCESS = 'access'
    DEFAULT_GW = 'default_gw'

    HOSTS = 'hosts'
    INSTANCE = 'instance'
    INSTANCES = 'instances'
    INSTANCE_INDEX = 'instance_index'
    GUESTS = 'guests'
    GUEST_ID = 'guest_id'
    IP_ADDRESSES = 'ip_addrs'
    GATEWAYS = 'gateways'
    NAME = 'name'
    SUBNET = 'subnet'
    SERVICE_SCAN_STATE = 'service_scan_state'
    SERVICE_EXPLOIT_STATE = 'service_exploit_state'
    OS_SCAN_STATE = 'os_scan_state'
    SUBNET_INSTANCE = 'subnet_instance'
    BRIDGES = 'bridges'

    # Constant values for PenGymNetwork, PenGymHostVector
    TAG_NASIM_PENGYM = 'nasim/pengym'
    TAG_NASIM = '  [nasim]'
    TAG_PENGYM = ' [pengym]'
    PENGYM = 'pengym'
    NASIM = 'nasim'
    USER = 'USER'
    ROOT = 'ROOT'

    # Constant values for actions (Metasploit modules)
    SSH = 'ssh'
    FTP = 'ftp'
    HTTP = 'http'
    SAMBA = 'samba'
    SMTP = 'smtp'

    TOMCAT = 'tomcat'
    PKEXEC = 'pkexec'
    PROFTPD = 'proftpd'
    CRON = 'cron'

    RHOSTS = 'RHOSTS'
    RPORT = 'RPORT'
    LHOST = 'LHOST'
    LPORT = 'LPORT'

    USERNAME = 'USERNAME'
    PASS_FILE = 'PASS_FILE'
    SSH_TIMEOUT = 'SSH_TIMEOUT'
    ACCOUNT = 'account'
    PWD_FILE = 'pwd_file'
    E_SSH_PWD_FILE = 'e_ssh_pwd_file'

    SSL_MODULE_ARG = 'SSL'
    SESSION = 'SESSION'
    VERBOSE = 'VERBOSE'
    CLEANUP = 'CLEANUP'
    WFSDElAY = 'WfsDelay'
    AUTO_CHECK = 'AutoCheck'
    FORCE_EXPLOIT = 'ForceExploit'

    DEACTIVE_CRON = 'deactive_cron'
    DEACTIVE_PE_TOMCAT = 'deactive_pe_tomcat'

    SMB_FOLDER = 'SMB_FOLDER'
    FAKE_BIND = 'DCERPC::fake_bind_multi'
    FORCE_EXPLOIT = 'ForceExploit'
    EXPECT_TIMEOUT = 'ExpectTimeout'
    CONNECT_TIMEOUT = 'ConnectTimeout'
    CMD = "cmd"
    X64 = "x64"

    # Constant values for creating cyber range
    ## File paths
    FILE_PATH = 'file_path'
    CYRIS_DESCRIPTION_FILE = 'cyris_description_file'
    SCENARIO_FILE = 'scenario_file'
    FIREWALL_RULE_PATH = 'firewall_rule_path'

    ## Host settings
    HOST_SETTINGS = 'host_settings'
    ID = 'id'
    MGMT_ADDR = 'mgmt_addr'
    HOST_MGMT_ADDR ='host_mgmt_addr'
    VIRBR_ADDR = 'virbr_addr'

    ## Guest settings
    GUEST_SETTINGS = 'guest_settings'
    BASEVM_HOST = 'basevm_host'
    BASEVM_CONFIG_FILE = 'basevm_config_file'
    BASEVM_TYPE = 'basevm_type'
    BASEVM_OS_TYPE = 'basevm_os_type'
    TASKS = 'tasks'

    ADD_ACCOUNT = 'add_account'
    PASSWD = 'passwd'

    INSTALL_PACKAGE = 'install_package'
    PACKAGE_MANAGER = 'package_manager'

    COPY_CONTENT = 'copy_content'
    SRC = 'src'
    DST = 'dst'

    EXECUTE_PROGRAM = 'execute_program'
    CONFIG_FIREWALL_STOP_SSH = 'config_firewall_stop_ssh'
    STOP_SSH = 'stop_ssh'
    PROGRAMS = 'programs'
    PROGRAM = 'program'
    ARGS ='args'
    INTERPRETER = 'interpreter'
    BASH = 'bash'
    AFTER_CLONE = 'after_clone'
    EXECUTE_TIME = 'execute_time'

    ## Clone settings
    CLONE_SETTINGS = 'clone_settings'
    RANGE_ID = 'range_id'
    HOST_ID = 'host_id'
    INSTANCE_NUMBER = 'instance_number'
    TOPOLOGY = 'topology'
    TYPE = 'type'
    ENTRY_POINT = 'entry_point'
    NUMBER = 'number'

    ## Scenario-based script constant
    SUBNETS = 'subnets'
    HOST_CONFIGS = 'host_configurations'

    # Constant values for creating firewall rule scripts
    NET_IPV4_FWD = 'sysctl -w net.ipv4.ip_forward=1'
    CLEAR_FIREWALL = 'iptables -F'
    DROP_INPUT = 'iptables -P INPUT DROP'
    SAVE_FIREWALL = 'iptables-save > firewall_original'
    SAVE = 'save'
    RESTORE = 'restore'
    MEMBERS = 'members'
    HOST = 'host'
    FIREWALL = 'firewall'
