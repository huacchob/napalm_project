from netmiko import SSHDetect
from napalm import get_network_driver
from napalm.base import NetworkDriver
from nornir import InitNornir
from nornir_napalm.plugins.tasks import napalm_configure
from netutils.lib_mapper import NETMIKO_LIB_MAPPER_REVERSE, NAPALM_LIB_MAPPER_REVERSE
from jinja2 import Environment, FileSystemLoader
import os
import yaml
from typing import Dict, List, Optional, Tuple, Type

"""
This script is meant to connect to Devices via NAPALM.
Finds NAPALM drivers and connects to each one.
"""


class UtilityMixin:
    """
    Class for utility functions.
    """

    def find_current_dir(self) -> str:
        """
        Find current directory.
        """
        return os.path.dirname((__file__))

    def add_forward_slash(self, path: str) -> str:
        """
        Add forward slash to path
        path = str representing a path.
        """
        if not path.startswith("/"):
            path = f"/{path}"
        if not path.endswith("/"):
            path = f"{path}/"
        return path

    def read_yaml_file(self, file_path: str, file_name: str) -> Dict:
        """
        Read yaml file
        file_path = str representing a path.
        file_name = str representing a file name.
        """
        vars_file_name = (
            f"{self.find_current_dir()}{self.add_forward_slash(file_path)}{file_name}"
        )
        with open(vars_file_name, "r", encoding="utf-8") as vars_file:
            return yaml.safe_load(vars_file)


class NornirInitializer(UtilityMixin):

    def __init__(
        self,
        nornir_dir: str,
    ):
        self.nornir_dir = nornir_dir

    def configure_nornir(self):
        """
        Configure nornir.
        """
        nornir_dir = self.add_forward_slash(self.nornir_dir)
        nr = InitNornir(
            config_file=f"{self.find_current_dir()}{nornir_dir}config.yaml",
        )
        return nr


class Jinja2Environment(UtilityMixin):
    """
    Class for jinja2 environment.
    """

    def __init__(
        self,
        template_dir: str,
        template_name: str,
        config_dir: str,
        config_file: str,
        j2_vars: Optional[dict],
    ):
        """
        template_dir: str - directory of jinja2 templates
        template_name: str - name of jinja2 template
        config_dir: str - directory of config files
        config_file: str - name of config file
        j2_vars: list - dictionary of jinja2 variables
            the key is the config name and the value should be a list
            The list should contain dictionaries of variables
            Example:
            {"config_1": [
                {
                    "var_name_1": "value_1",
                    "var_name_2": "value_2",
                },
                {
                    "var_name_1": "value_1",
                    "var_name_2": "value_2",
                },
            ],
            "config_2": [
                {
                    "var_name_1": "value_1",
                    "var_name_2": "value_2",
                },
                {
                    "var_name_1": "value_1",
                    "var_name_2": "value_2",
                },
            ],
            }
        """
        self.template_dir = template_dir
        self.template_name = template_name
        self.config_dir = config_dir
        self.config_file = config_file
        self.j2_vars = j2_vars
        self.jinja_env = self.setup_jinja2_env()
        self.j2_rendered_template = self.render_jinja2_variables()

    def setup_jinja2_env(self) -> Environment:
        """
        Setup jinja2 environment.
        """
        template_rel_dir_path = self.add_forward_slash(self.template_dir)
        template_directory = f"{self.find_current_dir()}{template_rel_dir_path}"
        return Environment(loader=FileSystemLoader(template_directory))

    def render_jinja2_variables(self) -> str:
        """
        Render jinja2 variables.
        """
        template = self.jinja_env.get_template(self.template_name)
        jinja_vars = (
            template.render(self.read_yaml_file("j2_vars", "ios.yml"))
            if not self.j2_vars
            else template.render(self.j2_vars)
        )
        return jinja_vars

    def create_config_file(self) -> str:
        """
        Create config file.
        """
        config_file_path = f"{self.find_current_dir()}{self.add_forward_slash(self.config_dir)}{self.config_file}"
        with open(config_file_path, "w", encoding="utf-8") as config_file:
            config_file.write(self.j2_rendered_template)
        print("Created Jinja2 environemnt and rendered a config file")

        return config_file_path


class NetmikoDriverGuesser:
    """
    Class for guessing the netmiko driver.
    """

    def __init__(
        self,
        device_ips: list,
        username: str,
        secret: Optional[str],
        password: str,
    ):
        """
        device_ips: list - list of device ips to connect to
        username: str - username to connect with
        password: str - password to connect with
        secret: str - secret to connect with (OPTIONAL if secret is different than password)
        """
        self.device_ips = device_ips
        self.username = username
        self.secret = secret
        self.password = password
        self.list_of_netmiko_device_params = self.create_netmiko_device_params()

    def create_netmiko_device_params(self) -> List[Dict]:
        """
        Create netmiko device params.
        """
        base_params = {
            "host": None,
            "username": self.username,
            "password": self.password,
            "secret": self.password,
            "device_type": "autodetect",
        }

        if self.secret:
            base_params.update({"secret": self.secret})

        device_conn_params: List[Dict] = []
        for ip in self.device_ips:
            base_param_copy = base_params.copy()
            base_param_copy.update({"host": ip})
            device_conn_params.append(base_param_copy)
        return device_conn_params

    def get_netmiko_platform(self) -> List[str]:
        """
        Get netmiko platform.
        """
        netmiko_platforms = []
        for device_param in self.list_of_netmiko_device_params:
            guessed_platform = SSHDetect(**device_param).autodetect()
            netmiko_platforms.append(guessed_platform)
        print("Guessed netmiko drivers")

        return netmiko_platforms


class NapalmDriverGuesser:
    """
    Class for guessing the napalm driver.
    """

    def __init__(
        self,
        netmiko_guesser: List[str],
    ):
        """
        netmiko_guesser: NetmikoDriverGuesser - netmiko driver guesser
        """
        self.netmiko_guesser = netmiko_guesser
        self.list_of_normalized_netmiko_platforms: List[str] = (
            self.normalize_netmiko_platform()
        )

    def normalize_netmiko_platform(self) -> List[str]:
        """
        Normalized netmiko platform.
        Using NETMIKO_LIB_MAPPER_REVERSE.
        """
        normalized_platforms: List[str] = [
            NETMIKO_LIB_MAPPER_REVERSE.get(platform, "")
            for platform in self.netmiko_guesser
        ]

        return normalized_platforms

    def get_napalm_driver(self) -> List[Type[NetworkDriver]]:
        """
        Get napalm driver.
        """
        napalm_netutils_drivers: List[str] = [
            NAPALM_LIB_MAPPER_REVERSE.get(platform, "")
            for platform in self.list_of_normalized_netmiko_platforms
        ]
        napalm_drivers: List[Type[NetworkDriver]] = []
        for driver in napalm_netutils_drivers:
            napalm_drivers.append(get_network_driver(driver))

        print("Guessed napalm drivers")

        return napalm_drivers


class NapalmDeviceConnection:
    """
    Class for connecting to a device using NAPALM.
    """

    def __init__(
        self,
        jinja_config_file_path: str,
        napalm_drivers: List[type[NetworkDriver]],
        device_ips: list,
        username: str,
        password: str,
        secret: Optional[str],
    ):
        """
        jinja_config_file_path: Jinja2Environment - jinja2 environment
        napalm_drivers: NapalmDriverGuesser - napalm driver guesser
        device_ips: list - list of device ips to connect to
        username: str - username to connect with
        password: str - password to connect with
        secret: str - secret to connect with
        """
        self.jinja_config_file_path = jinja_config_file_path
        self.napalm_drivers = napalm_drivers
        self.device_ips = device_ips
        self.username = username
        self.password = password
        self.secret = secret
        self.list_of_napalm_device_params: List[Dict] = (
            self.create_napalm_device_params()
        )
        self.list_of_device_connections: List[NetworkDriver] = self.connect_to_device()

    def create_napalm_device_params(self) -> List[Dict]:
        """
        Create napalm device params.
        """
        base_params = {
            "hostname": None,
            "username": self.username,
            "password": self.password,
            "optional_args": {
                "secret": self.password,
                "inline_transfer": True,
            },
        }

        if self.secret:
            base_params.update({"secret": self.secret})

        device_conn_params = []
        for ip in self.device_ips:
            copy_params = base_params.copy()
            copy_params.update({"hostname": ip})
            device_conn_params.append(copy_params)
        return device_conn_params

    def connect_to_device(self) -> List[NetworkDriver]:
        """
        Connect to device.
        """
        driver_and_param: List[Tuple] = list(
            zip(self.napalm_drivers, self.list_of_napalm_device_params)
        )
        connections: List[NetworkDriver] = [
            item[0](**item[1]) for item in driver_and_param
        ]

        return connections

    def send_config_file(self) -> List[NetworkDriver]:
        """
        Send config file.
        """
        devices_w_loaded_config = []
        for device_conn in self.list_of_device_connections:
            device_conn.open()
            device_conn.load_merge_candidate(filename=self.jinja_config_file_path)
            devices_w_loaded_config.append(device_conn)
        print("Connected to devices and loaded configs")
        return self.list_of_device_connections

    def commit_config(self) -> List[NetworkDriver]:
        """
        Commit config.
        """
        self.list_of_device_connections: List[NetworkDriver] = self.send_config_file()
        for conn in self.list_of_device_connections:
            conn.commit_config()
        return self.list_of_device_connections

    def return_saved_configs(self):
        """
        Return saved configs and close connections.
        """
        self.list_of_device_connections = self.commit_config()
        for conn in self.list_of_device_connections:
            device_config = conn.get_config().get("startup")
            print(device_config)
            conn.close()
        print("Finished pushing configs")


def connect_to_device(
    device_ips: list[str],
    username: str,
    password: str,
    secret: Optional[str],
    j2_vars: Optional[dict],
    template_dir: str,
    template_name: str,
    config_dir: str,
    config_file: str,
):
    """
    Connect to device.
    Function is meant to bring together all classes.
    """
    jinja_config_file_path = Jinja2Environment(
        template_dir=template_dir,
        template_name=template_name,
        config_dir=config_dir,
        config_file=config_file,
        j2_vars=j2_vars,
    ).create_config_file()

    netmiko_guesser = NetmikoDriverGuesser(
        device_ips=device_ips,
        username=username,
        password=password,
        secret=secret,
    ).get_netmiko_platform()

    napalm_guesser = NapalmDriverGuesser(
        netmiko_guesser=netmiko_guesser
    ).get_napalm_driver()

    NapalmDeviceConnection(
        jinja_config_file_path=jinja_config_file_path,
        napalm_drivers=napalm_guesser,
        device_ips=device_ips,
        username=username,
        password=password,
        secret=secret,
    ).return_saved_configs()


device_ips = [
    "192.168.86.52",
]

j2_vars = {
    "loopbacks": [
        {
            "interface_name": "lo1",
            "ip": "2.2.2.2",
            "subnet": "255.255.255.255",
        },
        {
            "interface_name": "lo2",
            "ip": "3.3.3.3",
            "subnet": "255.255.255.255",
        },
    ],
}

connect_to_device(
    device_ips=device_ips,
    username="admin",
    password="cisco",
    secret=None,
    j2_vars=None,
    template_dir="\\templates\\",
    template_name="full_config.j2",
    config_dir="\\intended_config\\",
    config_file="config.txt",
)
