"""A plugin structure"""

import dataclasses
import inspect
import os
import pkgutil


@dataclasses.dataclass(frozen=True)
class LogEvent():
    """The base class for an event."""
    etype: str
    level: int
    log: str


class Plugin():
    """Base class that each plugin must inherit from. Within this class
    you must define the methods that all of your plugins must implement
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        self.description = 'UNKNOWN'

    async def perform_operation(self, cfg, logger):
        """The method that we expect all plugins to implement. This is the
        method that our framework will call
        """
        raise NotImplementedError


class PluginCollection():
    """Upon creation, this class will read the plugins package for modules
    that contain a class definition that is inheriting from the Plugin class
    """

    def __init__(self, cfg, logger, plugin_package):
        """Constructor that initiates the reading of all available plugins
        when an instance of the PluginCollection object is created
        """
        self.plugin_package = plugin_package
        self.cfg = cfg
        self.logger = logger
        self.plugins = []
        self.seen_paths = []


    def __await__(self):
        return self.async_init().__await__()


    async def async_init(self):
        """Constructor that initiates the reading of all available plugins
        when an instance of the PluginCollection object is created
        """
        await self.reload_plugins()
        await self.apply_all_plugins()


    async def reload_plugins(self):
        """Reset the list of all plugins and initiate the walk over the main
        provided plugin package to load all available plugins
        """
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f'[plugins] Looking for plugins under package {self.plugin_package}'
            )
        )
        await self.walk_package(self.plugin_package)


    async def apply_all_plugins(self):
        """Apply all of the plugins
        """
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log='[plugins] ----- Applying all plugins -----'
            )
        )
        for plugin in self.plugins:
            await self.cfg.mainq.put(LogEvent(etype="log", level=20, log=""))
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f'[plugins] >>>>> Applying \'{plugin.description}\' <<<<<'
                )
            )
            await plugin.perform_operation(self.cfg, self.logger)

    async def walk_package(self, package):
        """Recursively walk the supplied package to retrieve all plugins
        """
        imported_package = __import__(package, fromlist=['blah'])

        for _, pluginname, ispkg in pkgutil.iter_modules(
            imported_package.__path__, imported_package.__name__ + '.'
        ):
            if not ispkg:
                plugin_module = __import__(pluginname, fromlist=['blah'])
                clsmembers = inspect.getmembers(plugin_module, inspect.isclass)
                for (_, cls) in clsmembers:
                    # Only add classes that are a sub class of Plugin, but NOT Plugin itself
                    if issubclass(cls, Plugin) & (cls is not Plugin):
                        await self.cfg.mainq.put(
                            LogEvent(
                                etype="log",
                                level=10,
                                log=f'[plugins] Found plugin class: {cls.__module__}.{cls.__name__}'
                            )
                        )
                        self.plugins.append(cls())


        # Now that we have looked at all the modules in the current package, start looking
        # recursively for additional modules in sub packages
        all_current_paths = []
        if isinstance(imported_package.__path__, str):
            all_current_paths.append(imported_package.__path__)
        else:
            all_current_paths.extend(imported_package.__path__)

        for pkg_path in all_current_paths:
            if pkg_path not in self.seen_paths:
                self.seen_paths.append(pkg_path)

                # Get all sub directory of the current package path directory
                child_pkgs = [
                    p for p in os.listdir(pkg_path)
                    if os.path.isdir(os.path.join(pkg_path, p))
                ]

                # For each sub directory, apply the walk_package method recursively
                for child_pkg in child_pkgs:
                    await self.walk_package(package + '.' + child_pkg)
