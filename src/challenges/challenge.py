from abc import ABC, abstractmethod, abstractproperty


class Challenge(ABC):

    @abstractproperty
    def title(self):
        pass

    @abstractproperty
    def subtitle(self):
        pass

    @abstractproperty
    def description(self):
        pass

    @abstractmethod
    def run_instance(self, container_name):
        pass

    @abstractmethod
    def remove_instance(self, container_name):
        pass

    @abstractmethod
    def build_challenge(self):
        pass
