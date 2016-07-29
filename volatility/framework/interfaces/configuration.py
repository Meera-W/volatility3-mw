from abc import ABCMeta, abstractmethod

from volatility.framework import validity

__author__ = 'mike'

CONFIG_SEPARATOR = "."


def path_join(*args):
    """Joins the config paths together"""
    return CONFIG_SEPARATOR.join(args)


class RequirementInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class to distinguish configuration elements from everything else"""

    def __init__(self, name, description = None, default = None, optional = False):
        validity.ValidityRoutines.__init__(self)
        self._check_type(name, str)
        if CONFIG_SEPARATOR in name:
            raise ValueError("Name cannot contain the config-hierarchy divider (" + CONFIG_SEPARATOR + ")")
        self._name = name
        self._description = description or ""
        self._default = default
        self._optional = optional
        self._requirements = {}

    def __repr__(self):
        return "<" + self.__class__.__name__ + ": " + self.name + ">"

    @property
    def name(self):
        """The name of the Option."""
        return self._name

    @property
    def description(self):
        """A short description of what the Option is designed to affect or achieve."""
        return self._description

    @property
    def default(self):
        """Returns the default value if one is set"""
        return self._default

    @property
    def optional(self):
        """Whether the option is required for or not"""
        return self._optional

    def config_value(self, context, config_path, default = None):
        """Returns the value for this element from its config path"""
        return context.config.get(path_join(config_path, self.name), default)

    # Child operations
    @property
    def requirements(self):
        """Returns an iterator of all the child requirements"""
        for child in self._requirements:
            yield self._requirements[child]

    def add_requirement(self, requirement):
        """Adds a child to the list of requirements"""
        self._check_type(requirement, RequirementInterface)
        self._requirements[requirement.name] = requirement

    def remove_requirement(self, requirement):
        """Removes a child from the list of requirements"""
        self._check_type(requirement, RequirementInterface)
        del self._requirements[requirement.name]

    def validate_children(self, context, config_path):
        """Method that will validate all child requirements"""
        return all([requirement.validate(context, path_join(config_path, self._name)) for requirement in
                    self.requirements if not requirement.optional])

    # Validation routines
    @abstractmethod
    def validate(self, context, config_path):
        """Method to validate the value stored at config_path for the configuration object against a context

           Returns False when an item is invalid
        """


class ConfigurableInterface(validity.ValidityRoutines):
    """Class to allow objects to have requirements and read configuration data from the context config tree"""

    def __init__(self, config_path):
        """Basic initializer that allows configurables to access their own config settings"""
        validity.ValidityRoutines.__init__(self)
        self._config_path = self._check_type(config_path, str)

    @classmethod
    def get_requirements(cls):
        """Returns a list of RequirementInterface objects  required by this object"""
        return []

    @classmethod
    def validate(cls, context, config_path):
        return all([requirement.validate(context, config_path) for requirement in cls.get_requirements() if
                    not requirement.optional])


class RequirementTreeNode(validity.ValidityRoutines):
    def __init__(self, requirement = None):
        validity.ValidityRoutines.__init__(self)
        if requirement is not None:
            self._check_type(requirement, RequirementInterface)
        self.requirement = requirement

    def traverse(self, visitor, config_path = None, short_circuit = False):
        """Applies the function visitor to each node

        The visitor callable should have a signature of visitor(node, config_path) => Bool

        When short_circuit is True:
          RequirementChoices will stop as soon as one traversal responds with True
          RequirementLists will stop as soon as one traversal responds with False
        When short_circuit is False the return value of children are always ignored

        Returns the result from visitor applied to the node
        """


class HierachicalVisitor(validity.ValidityRoutines):
    def branch_enter(self, node, config_path):
        """Called on entering a branch of a tree

           Returns a boolean indicating whether to process any children of this node
        """
        return True

    def branch_leave(self, node, config_path):
        """Called on leaving a branch of a tree

           Returns a boolean indicating whether to process any further siblings of this node
        """
        return True

    def __call__(self, node, config_path):
        """Designed to be called on each LEAF node in a tree

           Returns a boolean indiciating whether to process any further siblings of this node
        """
        return True
