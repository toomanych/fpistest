"""
COS Protocol Operator Class
Handles COS_OPREQ commands and COS/PSOS state reading for CG-type systems.
Simple, lightweight, synchronous operations for GUI integration.
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from opcua import Client
import logging

logger = logging.getLogger(__name__)


class COSCommand(Enum):
    """COS command values and descriptions"""
    GOTO_READY = (3, 'gotoReady')
    GOTO_LOCAL = (11, 'gotoLocal')
    GO_NOT_READY = (2, 'goNotReady')
    INITIALISE = (4, 'Initialise')
    ABORT = (9, 'Abort')
    EXECUTE = (6, 'Execute')
    POST_CHECK = (7, 'PostCheck')
    
    def __init__(self, value: int, description: str):
        self.value = value
        self.description = description


class COSState(Enum):
    """COS_OPSTATE values with display colors"""
    OFF = (1, 'OFF', '#800080')                    # Purple
    NOT_READY = (2, 'NOT_READY', '#0000FF')        # Blue
    READY = (3, 'READY', '#FFA500')                # Orange
    INITIALISING = (4, 'INITIALISING', '#808080')  # Gray
    INITIALISED = (5, 'INITIALISED', '#808080')    # Gray
    EXECUTING = (6, 'EXECUTING', '#00FF00')        # Green
    POST_PULSE_CHECKS = (7, 'POST_PULSE_CHECKS', '#FF0000')  # Red
    ABORTING = (9, 'ABORTING', '#808080')          # Gray
    LOCAL = (11, 'LOCAL', '#0000FF')               # Blue
    
    def __init__(self, value: int, name: str, color: str):
        self.value = value
        self.state_name = name
        self.color = color


class PSOSState(Enum):
    """PSOS_OPSTATE values"""
    OFF = (1, 'OFF')
    NOT_READY = (2, 'NOT_READY')
    READY = (3, 'READY')
    INITIALISING = (4, 'INITIALISING')
    INITIALISED = (5, 'INITIALISED')
    EXECUTING = (6, 'EXECUTING')
    POST_PULSE_CHECKS = (7, 'POST_PULSE_CHECKS')
    TERMINATING = (8, 'TERMINATING')
    ABORTING = (9, 'ABORTING')
    PLANT_ABORT_91 = (10, 'PLANT_ABORT_91')
    INHIBIT_NEXT_PULSE = (11, 'INHIBIT_NEXT_PULSE')
    LOCAL = (12, 'LOCAL')
    CONFIGURE = (13, 'CONFIGURE')
    PLANT_ABORT_92 = (14, 'PLANT_ABORT_92')
    
    def __init__(self, value: int, name: str):
        self.value = value
        self.state_name = name


@dataclass
class ServerConfig:
    """Configuration for a single server"""
    name: str
    url: str
    client: Optional[Client] = None
    connected: bool = False


@dataclass
class SystemState:
    """Current state of a system"""
    server_name: str
    connected: bool
    cos_state: Optional[COSState] = None
    psos_state: Optional[PSOSState] = None
    cos_raw_value: Optional[int] = None
    psos_raw_value: Optional[int] = None


@dataclass
class CommandResult:
    """Result of a COS command operation"""
    success: bool
    server_results: Dict[str, bool]  # server_name -> success
    error_message: Optional[str] = None


class COSOperator:
    """
    Handles COS_OPREQ commands and state reading for CG-type systems.
    Provides simple, synchronous operations for GUI integration.
    """
    
    def __init__(self):
        self.servers: Dict[str, ServerConfig] = {}
        
        # Create lookup dictionaries for states
        self.cos_states_by_value = {state.value: state for state in COSState}
        self.psos_states_by_value = {state.value: state for state in PSOSState}
        self.commands_by_value = {cmd.value: cmd for cmd in COSCommand}

    def add_server(self, name: str, url: str) -> bool:
        """Add a server configuration"""
        try:
            self.servers[name] = ServerConfig(name=name, url=url)
            logger.info("Added server configuration: {} -> {}".format(name, url))
            return True
        except Exception as e:
            logger.error("Failed to add server {}: {}".format(name, e))
            return False

    def remove_server(self, name: str) -> bool:
        """Remove a server configuration"""
        try:
            if name in self.servers:
                # Disconnect if connected
                if self.servers[name].connected:
                    self.disconnect_server(name)
                del self.servers[name]
                logger.info("Removed server configuration: {}".format(name))
                return True
            return False
        except Exception as e:
            logger.error("Failed to remove server {}: {}".format(name, e))
            return False

    def connect_server(self, name: str) -> bool:
        """Connect to a server"""
        if name not in self.servers:
            logger.error("Server {} not configured".format(name))
            return False
        
        server_config = self.servers[name]
        
        try:
            if server_config.client is None:
                server_config.client = Client(server_config.url)
            
            if not server_config.connected:
                server_config.client.connect()
                server_config.connected = True
                logger.info("Connected to server: {}".format(name))
            
            return True
            
        except Exception as e:
            logger.error("Failed to connect to server {}: {}".format(name, e))
            server_config.connected = False
            return False

    def disconnect_server(self, name: str) -> bool:
        """Disconnect from a server"""
        if name not in self.servers:
            return False
        
        server_config = self.servers[name]
        
        try:
            if server_config.client and server_config.connected:
                server_config.client.disconnect()
                server_config.connected = False
                logger.info("Disconnected from server: {}".format(name))
            return True
            
        except Exception as e:
            logger.error("Error disconnecting from server {}: {}".format(name, e))
            server_config.connected = False
            return False

    def is_server_connected(self, name: str) -> bool:
        """Check if server is connected"""
        if name not in self.servers:
            return False
        return self.servers[name].connected

    def get_connected_servers(self) -> List[str]:
        """Get list of connected server names"""
        return [name for name, config in self.servers.items() if config.connected]

    def write_cos_command_single(self, server_name: str, command: COSCommand) -> bool:
        """Write COS_OPREQ command to a single server"""
        if server_name not in self.servers:
            logger.error("Server {} not configured".format(server_name))
            return False
        
        server_config = self.servers[server_name]
        
        if not server_config.connected:
            logger.error("Server {} not connected".format(server_name))
            return False
        
        try:
            client = server_config.client
            objects = client.get_objects_node()
            
            # Write to CGX.COS.COS_OPREQ
            cos_opreq_node = objects.get_child(["1:CGX", "1:COS", "1:COS_OPREQ"])
            cos_opreq_node.set_value(command.value)
            
            logger.info("Wrote COS command to {}: {} ({})".format(
                server_name, command.description, command.value))
            return True
            
        except Exception as e:
            logger.error("Failed to write COS command to {}: {}".format(server_name, e))
            # Mark server as disconnected on communication failure
            server_config.connected = False
            return False

    def write_cos_command_multiple(self, server_names: List[str], command: COSCommand) -> CommandResult:
        """Write COS_OPREQ command to multiple servers"""
        server_results = {}
        overall_success = True
        error_messages = []
        
        for server_name in server_names:
            success = self.write_cos_command_single(server_name, command)
            server_results[server_name] = success
            
            if not success:
                overall_success = False
                error_messages.append("{}: failed".format(server_name))
        
        error_message = "; ".join(error_messages) if error_messages else None
        
        logger.info("Multi-server COS command {}: Success={}, Results={}".format(
            command.description, overall_success, server_results))
        
        return CommandResult(
            success=overall_success,
            server_results=server_results,
            error_message=error_message
        )

    def write_cos_command_all_connected(self, command: COSCommand) -> CommandResult:
        """Write COS_OPREQ command to all connected servers"""
        connected_servers = self.get_connected_servers()
        
        if not connected_servers:
            return CommandResult(
                success=False,
                server_results={},
                error_message="No servers connected"
            )
        
        return self.write_cos_command_multiple(connected_servers, command)

    def read_system_state(self, server_name: str) -> SystemState:
        """Read current COS and PSOS state from a server"""
        if server_name not in self.servers:
            return SystemState(server_name=server_name, connected=False)
        
        server_config = self.servers[server_name]
        
        if not server_config.connected:
            # Server not connected - return OFF states
            return SystemState(
                server_name=server_name,
                connected=False,
                cos_state=COSState.OFF,
                psos_state=PSOSState.OFF,
                cos_raw_value=COSState.OFF.value,
                psos_raw_value=PSOSState.OFF.value
            )
        
        try:
            client = server_config.client
            objects = client.get_objects_node()
            
            # Read COS_OPSTATE
            cos_opstate_node = objects.get_child(["1:CGX", "1:COS", "1:COS_OPSTATE"])
            cos_raw_value = cos_opstate_node.get_value()
            
            # Read PSOS_OPSTATE
            psos_opstate_node = objects.get_child(["1:CGX", "1:COS", "1:PSOS_OPSTATE"])
            psos_raw_value = psos_opstate_node.get_value()
            
            # Map to enum states
            cos_state = self.cos_states_by_value.get(cos_raw_value)
            psos_state = self.psos_states_by_value.get(psos_raw_value)
            
            return SystemState(
                server_name=server_name,
                connected=True,
                cos_state=cos_state,
                psos_state=psos_state,
                cos_raw_value=cos_raw_value,
                psos_raw_value=psos_raw_value
            )
            
        except Exception as e:
            logger.error("Failed to read state from {}: {}".format(server_name, e))
            # Mark server as disconnected on communication failure
            server_config.connected = False
            
            # Return OFF states for failed reads
            return SystemState(
                server_name=server_name,
                connected=False,
                cos_state=COSState.OFF,
                psos_state=PSOSState.OFF,
                cos_raw_value=COSState.OFF.value,
                psos_raw_value=PSOSState.OFF.value
            )

    def read_all_system_states(self) -> Dict[str, SystemState]:
        """Read current states from all configured servers"""
        states = {}
        
        for server_name in self.servers.keys():
            states[server_name] = self.read_system_state(server_name)
        
        return states

    def get_command_by_value(self, value: int) -> Optional[COSCommand]:
        """Get COS command enum by its integer value"""
        return self.commands_by_value.get(value)

    def get_cos_state_by_value(self, value: int) -> Optional[COSState]:
        """Get COS state enum by its integer value"""
        return self.cos_states_by_value.get(value)

    def get_psos_state_by_value(self, value: int) -> Optional[PSOSState]:
        """Get PSOS state enum by its integer value"""
        return self.psos_states_by_value.get(value)

    def get_available_commands(self) -> List[COSCommand]:
        """Get list of all available COS commands"""
        return list(COSCommand)

    def get_server_names(self) -> List[str]:
        """Get list of all configured server names"""
        return list(self.servers.keys())

    def update_server_url(self, name: str, new_url: str) -> bool:
        """Update server URL (requires reconnection)"""
        if name not in self.servers:
            return False
        
        try:
            # Disconnect if connected
            if self.servers[name].connected:
                self.disconnect_server(name)
            
            # Update URL and reset client
            self.servers[name].url = new_url
            self.servers[name].client = None
            
            logger.info("Updated server {} URL to: {}".format(name, new_url))
            return True
            
        except Exception as e:
            logger.error("Failed to update server {} URL: {}".format(name, e))
            return False

    def cleanup(self):
        """Disconnect all servers and cleanup resources"""
        for server_name in list(self.servers.keys()):
            try:
                self.disconnect_server(server_name)
            except Exception as e:
                logger.error("Error during cleanup of {}: {}".format(server_name, e))
        
        self.servers.clear()
        logger.info("COSOperator cleanup completed")


# Example usage for GUI integration
def create_example_cos_operator():
    """Example of how to create and use COSOperator"""
    
    # Create operator
    cos_operator = COSOperator()
    
    # Add servers (GUI would do this based on configuration)
    cos_operator.add_server('CG1', 'opc.tcp://4602tv-cpu-4201.codac.iter.org:4840')
    cos_operator.add_server('CG2', 'opc.tcp://4602tv-cpu-4202.codac.iter.org:4840')
    
    # Connect to servers
    cos_operator.connect_server('CG1')
    cos_operator.connect_server('CG2')
    
    # Send command to all connected servers
    result = cos_operator.write_cos_command_all_connected(COSCommand.GOTO_READY)
    print(f"Command result: {result}")
    
    # Send command to specific server
    success = cos_operator.write_cos_command_single('CG1', COSCommand.INITIALISE)
    print(f"Single server command: {success}")
    
    # Read states (GUI would call this every 300ms)
    states = cos_operator.read_all_system_states()
    for server_name, state in states.items():
        print(f"{server_name}: Connected={state.connected}")
        if state.cos_state:
            print(f"  COS: {state.cos_state.state_name} ({state.cos_raw_value})")
        if state.psos_state:
            print(f"  PSOS: {state.psos_state.state_name} ({state.psos_raw_value})")
    
    # Cleanup
    cos_operator.cleanup()
    
    return cos_operator


# GUI integration helper functions
def format_state_for_display(state: SystemState) -> Dict[str, Any]:
    """Format system state for GUI display"""
    if not state.connected:
        return {
            'connected': False,
            'cos_text': 'OFF (1)',
            'cos_color': COSState.OFF.color,
            'psos_text': 'OFF (1)',
            'psos_color': '#FFFFFF'  # White background for disconnected
        }
    
    cos_text = f"{state.cos_state.state_name} ({state.cos_raw_value})" if state.cos_state else f"Unknown ({state.cos_raw_value})"
    cos_color = state.cos_state.color if state.cos_state else '#CCCCCC'
    
    psos_text = f"{state.psos_state.state_name} ({state.psos_raw_value})" if state.psos_state else f"Unknown ({state.psos_raw_value})"
    psos_color = '#E0E0E0'  # Light gray for PSOS
    
    return {
        'connected': True,
        'cos_text': cos_text,
        'cos_color': cos_color,
        'psos_text': psos_text,
        'psos_color': psos_color
    }
