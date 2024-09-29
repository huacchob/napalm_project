"""
This script is meant to connect to Devices via NAPALM.
Finds NAPALM drivers and connects to each one.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, Union
from jinja2 import Environment, FileSystemLoader, Template

from napalm import get_network_driver  # type: ignore
from napalm.base import NetworkDriver  # type: ignore
from nornir import InitNornir
from nornir.core import Nornir
from netmiko import SSHDetect  # type: ignore
from netutils.lib_mapper import (
    NETMIKO_LIB_MAPPER_REVERSE,
    NAPALM_LIB_MAPPER_REVERSE,
)
import yaml

NoneOrStr = Union[None, str]
NetDrivers = List[NetworkDriver]


class UtilityMixin:
    """
    Class for utility functions.
    """

    def find_current_dir(self) -> Path:
        """
        Find current directory.
        """
        return Path(__file__).parent.resolve()

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

    def read_yaml_file(self, file_path: str, file_name: str) -> Dict[Any, Any]:
        """
        Read yaml file
        file_path = str representing a path.
        file_name = str representing a file name.
        """
        directory: Path = self.find_current_dir()
        vars_file_name: str = f"{directory}{self.add_forward_slash(
                file_path)}{file_name}"
        with open(vars_file_name, "r", encoding="utf-8") as vars_file:
            return yaml.safe_load(vars_file)


class NornirInitializer(UtilityMixin):
    def __init__(
        self,
        nornir_dir: str,
    ) -> None:
        self.nornir_dir: str = nornir_dir

    def configure_nornir(self) -> Nornir:
        """
        Configure nornir.
        """
        nornir_dir: str = self.add_forward_slash(self.nornir_dir)
        nr: Nornir = InitNornir(
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
        j2_vars: Optional[Dict[Any, Any]],
    ) -> None:
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
        self.template_dir: str = template_dir
        self.template_name: str = template_name
        self.config_dir: str = config_dir
        self.config_file: str = config_file
        self.j2_vars: Optional[Dict[Any, Any]] = j2_vars
        self.jinja_env: Environment = self.setup_jinja2_env()
        self.j2_rendered_template: str = self.render_jinja2_variables()
        self.directory: Path = self.find_current_dir()

    def setup_jinja2_env(self) -> Environment:
        """
        Setup jinja2 environment.
        """
        template_rel_dir_path: str = self.add_forward_slash(self.template_dir)
        template_directory: str = f"{self.directory}{template_rel_dir_path}"
        return Environment(loader=FileSystemLoader(template_directory))

    def render_jinja2_variables(self) -> str:
        """
        Render jinja2 variables.
        """
        template: Template = self.jinja_env.get_template(self.template_name)
        jinja_vars: str = (
            template.render(self.read_yaml_file("j2_vars", "ios.yml"))
            if not self.j2_vars
            else template.render(self.j2_vars)
        )
        return jinja_vars

    def create_config_file(self) -> str:
        """
        Create config file.
        """
        config_file_path: str = f"{self.directory}{self.add_forward_slash(
            self.config_dir)}{self.config_file}"
        with open(config_file_path, "w", encoding="utf-8") as config_file:
            config_file.write(self.j2_rendered_template)
        print("Created Jinja2 environment and rendered a config file")

        return config_file_path


class NetmikoDriverGuesser:
    """
    Class for guessing the netmiko driver.
    """

    def __init__(
        self,
        device_ips: list[str],
        username: str,
        secret: NoneOrStr,
        password: str,
    ) -> None:
        """
        device_ips: list - list of device ips to connect to
        username: str - username to connect with
        password: str - password to connect with
        secret: str - secret to connect with
            (OPTIONAL) secret: str - secret to connect with
            (OPTIONAL if secret is different than password)
        """
        self.device_ips: List[str] = device_ips
        self.username: str = username
        self.secret: NoneOrStr = secret
        self.password: str = password
        self.list_of_netmiko_device_params: List[Optional[Dict[Any, Any]]] = (
            self.create_netmiko_device_params()
        )

    def create_netmiko_device_params(self) -> List[Optional[Dict[Any, Any]]]:
        """
        Create netmiko device params.
        """
        base_params: Dict[str, Any] = {
            "host": None,
            "username": self.username,
            "password": self.password,
            "secret": self.password,
            "device_type": "autodetect",
        }

        if self.secret:
            base_params.update({"secret": self.secret})

        device_conn_params: List[Optional[Dict[Any, Any]]] = []
        for ip in self.device_ips:
            base_param_copy: Dict[str, Any] = base_params.copy()
            base_param_copy.update({"host": ip})
            device_conn_params.append(base_param_copy)
        return device_conn_params

    def get_netmiko_platform(self) -> List[NoneOrStr]:
        """
        Get netmiko platform.
        """
        netmiko_platforms: List[NoneOrStr] = []
        for device_param in self.list_of_netmiko_device_params:
            if device_param:
                guessed_platform: NoneOrStr = SSHDetect(
                    **device_param,
                ).autodetect()
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
        device_ips: List[str],
        username: str,
        password: str,
        secret: NoneOrStr,
    ) -> None:
        """
        jinja_config_file_path: Jinja2Environment - jinja2 environment
        napalm_drivers: NapalmDriverGuesser - napalm driver guesser
        device_ips: List[str] - list of device ips to connect to
        username: str - username to connect with
        password: str - password to connect with
        secret: str - secret to connect with
        """
        self.jinja_config_file_path: str = jinja_config_file_path
        self.napalm_drivers: List[type[NetworkDriver]] = napalm_drivers
        self.device_ips: List[str] = device_ips
        self.username: str = username
        self.password: str = password
        self.secret: NoneOrStr = secret
        self.list_of_napalm_device_params: List[Dict[Any, Any]] = (
            self.create_napalm_device_params()
        )
        self.list_of_device_connections: NetDrivers = self.connect_to_device()

    def create_napalm_device_params(self) -> List[Dict[Any, Any]]:
        """
        Create napalm device params.
        """
        base_params: Dict[
            str,
            Union[
                None,
                str,
                Dict[str, Union[str, bool]],
            ],
        ] = {
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

        device_conn_params: List[Dict[Any, Any]] = []
        for ip in self.device_ips:
            copy_params: Dict[Any, Any] = base_params.copy()
            copy_params.update({"hostname": ip})
            device_conn_params.append(copy_params)
        return device_conn_params

    def connect_to_device(self) -> NetDrivers:
        """
        Connect to device.
        """
        driver_and_param: List[
            Tuple[
                Type[NetworkDriver],
                Dict[Any, Any],
            ]
        ] = list(zip(self.napalm_drivers, self.list_of_napalm_device_params))
        connections: NetDrivers = [i[0](**i[1]) for i in driver_and_param]

        return connections

    def send_config_file(self) -> NetDrivers:
        """
        Send config file.
        """
        devices_w_loaded_config: List[Optional[NetworkDriver]] = []
        for device_conn in self.list_of_device_connections:
            device_conn.open()
            device_conn.load_merge_candidate(
                filename=self.jinja_config_file_path,
            )
            devices_w_loaded_config.append(device_conn)
        print("Connected to devices and loaded configs")
        return self.list_of_device_connections

    def commit_config(self) -> NetDrivers:
        """
        Commit config.
        """
        self.list_of_device_connections: NetDrivers = self.send_config_file()
        for conn in self.list_of_device_connections:
            conn.commit_config()
        return self.list_of_device_connections

    def return_saved_configs(self) -> None:
        """
        Return saved configs and close connections.
        """
        self.list_of_device_connections = self.commit_config()
        for conn in self.list_of_device_connections:
            device_config: str = conn.get_config().get("startup")
            print(device_config)
            conn.close()
        print("Finished pushing configs")


def connect_to_device(
    device_ips: list[str],
    username: str,
    password: str,
    secret: NoneOrStr,
    j2_vars: Optional[Dict[Any, Any]],
    template_dir: str,
    template_name: str,
    config_dir: str,
    config_file: str,
) -> None:
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

    napalm_guesser: List[type[NetworkDriver]] = NapalmDriverGuesser(
        netmiko_guesser=netmiko_guesser  # type: ignore
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
