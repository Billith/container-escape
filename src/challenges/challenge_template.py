from challenges.challenge import Challenge
from main import app
import utils


class Challenge_template(Challenge):

    def __init__(self, client, solved_challenges):
        self.client = client
        self.solved_challenges = solved_challenges

    @property
    def title(self):
        return 'Challenge template title'

    @property
    def subtitle(self):
        return 'subtitle'

    @property
    def description(self):
        return '''description'''

    def run_instance(self, container_name):
        pass

    def remove_instance(self, container_name):
        pass

    def build_challenge(self):
        pass
