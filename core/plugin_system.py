#!/usr/bin/env python3
"""
DDOS Protector - Plugin System

This module provides a simple plugin architecture for extending DDOS Protector
with new detection methods, blocking mechanisms, or notification systems.

Usage:
    1. Create a new plugin in the plugins/ directory
    2. Implement the required interface methods
    3. Enable in config.yaml
    4. Plugin loads automatically on service restart

Example Plugin:
    See plugins/example_plugin.py for a template
"""

import os
import sys
import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger('scr-protector.plugins')

# =============================================================================
# PLUGIN INTERFACES
# =============================================================================

@dataclass
class SecurityEvent:
    """Represents a security event detected by the system."""
    ip: str
    timestamp: datetime
    event_type: str
    severity: str  # INFO, WARN, ALERT
    details: str
    source: str  # Which component detected this


class DetectorPlugin(ABC):
    """
    Base class for detection plugins.
    
    Implement this to add new threat detection methods.
    Examples: Port scan detection, payload analysis, geo-blocking
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the plugin with configuration.
        Return True if successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """
        Analyze incoming data and return a SecurityEvent if threat detected.
        Return None if no threat found.
        
        Args:
            data: Dict containing log line data or network data
        """
        pass
    
    def cleanup(self):
        """Called when plugin is unloaded."""
        pass


class ActionPlugin(ABC):
    """
    Base class for action plugins.
    
    Implement this to add new response actions.
    Examples: Webhook notifications, SMS alerts, Slack messages
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    def execute(self, event: SecurityEvent) -> bool:
        """
        Execute action in response to security event.
        Return True if action succeeded.
        """
        pass
    
    def cleanup(self):
        """Called when plugin is unloaded."""
        pass


class BlockerPlugin(ABC):
    """
    Base class for blocker plugins.
    
    Implement this to add new blocking mechanisms.
    Examples: Cloudflare API, AWS WAF, custom firewall
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    def block(self, ip: str, reason: str, duration: Optional[int] = None) -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Why the IP is being blocked
            duration: Optional duration in seconds (None = permanent)
        """
        pass
    
    @abstractmethod
    def unblock(self, ip: str) -> bool:
        """Unblock an IP address."""
        pass
    
    @abstractmethod
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        pass
    
    def cleanup(self):
        """Called when plugin is unloaded."""
        pass


# =============================================================================
# PLUGIN MANAGER
# =============================================================================

class PluginManager:
    """
    Manages plugin discovery, loading, and lifecycle.
    """
    
    def __init__(self, plugins_dir: str = None):
        self.plugins_dir = plugins_dir or '/opt/scr-protector/plugins'
        self.detectors: Dict[str, DetectorPlugin] = {}
        self.actions: Dict[str, ActionPlugin] = {}
        self.blockers: Dict[str, BlockerPlugin] = {}
        self._hooks: Dict[str, List[Callable]] = {
            'on_event': [],
            'on_block': [],
            'on_unblock': [],
            'on_alert': [],
        }
    
    def discover_plugins(self) -> List[str]:
        """Find all plugin files in the plugins directory."""
        plugins_path = Path(self.plugins_dir)
        if not plugins_path.exists():
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return []
        
        plugin_files = []
        for f in plugins_path.glob('*.py'):
            if not f.name.startswith('_'):
                plugin_files.append(str(f))
        
        return plugin_files
    
    def load_plugin(self, filepath: str, config: Dict[str, Any] = None) -> bool:
        """
        Load a single plugin from file.
        
        Args:
            filepath: Path to plugin .py file
            config: Configuration dict for the plugin
        """
        try:
            spec = importlib.util.spec_from_file_location("plugin", filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes in module
            loaded = False
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, type):
                    if issubclass(obj, DetectorPlugin) and obj != DetectorPlugin:
                        plugin = obj()
                        if plugin.initialize(config or {}):
                            self.detectors[plugin.name] = plugin
                            logger.info(f"Loaded detector plugin: {plugin.name} v{plugin.version}")
                            loaded = True
                    
                    elif issubclass(obj, ActionPlugin) and obj != ActionPlugin:
                        plugin = obj()
                        if plugin.initialize(config or {}):
                            self.actions[plugin.name] = plugin
                            logger.info(f"Loaded action plugin: {plugin.name} v{plugin.version}")
                            loaded = True
                    
                    elif issubclass(obj, BlockerPlugin) and obj != BlockerPlugin:
                        plugin = obj()
                        if plugin.initialize(config or {}):
                            self.blockers[plugin.name] = plugin
                            logger.info(f"Loaded blocker plugin: {plugin.name} v{plugin.version}")
                            loaded = True
            
            return loaded
        
        except Exception as e:
            logger.error(f"Failed to load plugin {filepath}: {e}")
            return False
    
    def load_all(self, config: Dict[str, Any] = None):
        """Load all discovered plugins."""
        for filepath in self.discover_plugins():
            plugin_name = Path(filepath).stem
            plugin_config = (config or {}).get('plugins', {}).get(plugin_name, {})
            
            # Check if plugin is enabled
            if plugin_config.get('enabled', True):
                self.load_plugin(filepath, plugin_config)
    
    def unload_all(self):
        """Cleanup and unload all plugins."""
        for plugin in list(self.detectors.values()):
            plugin.cleanup()
        for plugin in list(self.actions.values()):
            plugin.cleanup()
        for plugin in list(self.blockers.values()):
            plugin.cleanup()
        
        self.detectors.clear()
        self.actions.clear()
        self.blockers.clear()
    
    # -------------------------------------------------------------------------
    # Hook System
    # -------------------------------------------------------------------------
    
    def register_hook(self, hook_name: str, callback: Callable):
        """Register a callback for a specific hook."""
        if hook_name in self._hooks:
            self._hooks[hook_name].append(callback)
    
    def trigger_hook(self, hook_name: str, *args, **kwargs):
        """Trigger all callbacks for a hook."""
        for callback in self._hooks.get(hook_name, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"Hook {hook_name} callback failed: {e}")
    
    # -------------------------------------------------------------------------
    # Detection
    # -------------------------------------------------------------------------
    
    def run_detectors(self, data: Dict[str, Any]) -> List[SecurityEvent]:
        """Run all detector plugins on input data."""
        events = []
        for detector in self.detectors.values():
            try:
                event = detector.analyze(data)
                if event:
                    events.append(event)
                    self.trigger_hook('on_event', event)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed: {e}")
        return events
    
    # -------------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------------
    
    def run_actions(self, event: SecurityEvent):
        """Run all action plugins for an event."""
        for action in self.actions.values():
            try:
                action.execute(event)
            except Exception as e:
                logger.error(f"Action {action.name} failed: {e}")
    
    # -------------------------------------------------------------------------
    # Blocking
    # -------------------------------------------------------------------------
    
    def block_ip(self, ip: str, reason: str, duration: int = None) -> bool:
        """Block IP using all blocker plugins."""
        success = False
        for blocker in self.blockers.values():
            try:
                if blocker.block(ip, reason, duration):
                    success = True
            except Exception as e:
                logger.error(f"Blocker {blocker.name} failed: {e}")
        
        if success:
            self.trigger_hook('on_block', ip, reason)
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP from all blocker plugins."""
        success = False
        for blocker in self.blockers.values():
            try:
                if blocker.unblock(ip):
                    success = True
            except Exception as e:
                logger.error(f"Blocker {blocker.name} failed: {e}")
        
        if success:
            self.trigger_hook('on_unblock', ip)
        return success


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None

def get_plugin_manager() -> PluginManager:
    """Get or create the global plugin manager."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


def init_plugins(config: Dict[str, Any] = None, plugins_dir: str = None):
    """Initialize the plugin system."""
    global _plugin_manager
    _plugin_manager = PluginManager(plugins_dir)
    _plugin_manager.load_all(config)
    return _plugin_manager
