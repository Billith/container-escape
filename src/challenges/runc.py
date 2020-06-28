import subprocess
import threading
import datetime
import docker
import time
import os
import re

from challenges.challenge import Challenge
from main import app
import utils


class Runc(Challenge):

    def __init__(self, client, solved_challenges):
        self.client = client
        self.solved_challenges = solved_challenges
        self.lock = threading.Lock()
        threading.Thread(target=self.trigger).start()
        threading.Thread(target=self.win_check).start()

    @property
    def title(self):
        return 'RunC vulnerability'

    @property
    def subtitle(self):
        return 'CVE-2019-5736'

    @property
    def description(self):
        return '''Runc through 1.0-rc6 allows attackers to overwrite the 
            host runc binary by leveraging the ability to execute a command as 
            root within container'''

    def run_instance(self, container_name, keepalive_containers):
        self.lock.acquire()
        port = utils.get_free_port()

        if port == -1:
            raise Exception("failed to run instance, couldn't find available port")

        try:
            # Running host container is implemented with subprocess call, because
            # docker python SDK do not support "--experimental" flag and I couldn't
            # find the way, to enable it through some config file or env variable.
            run_cmd = ' '.join(
                [
                    '/usr/bin/docker',
                    'run',
                    f'-p {port}:{port}',
                    '--privileged',
                    '--rm',
                    f'--name {container_name}',
                    '-d',
                    '-e DOCKER_HOST=unix:///run/user/1000/docker.sock',
                    '--memory=64m',
                    '--memory-swap=64m',
                    # '--cpus=0.25',
                    'runc_vuln_host',
                    '--experimental',
                ]
            )
            result = subprocess.getoutput(run_cmd)
            # Docker client prints warning when memory limitations are used, so
            # we cannot be sure that command output will be only id of spawned
            # container. That's why regex below is required to find this id.
            # Example:
            #   WARNING: Your kernel does not support swap limit capabilities or
            #   the cgroup is not mounted. Memory limited without swap.
            #   ad9d0928ad507baa9e4fadcf6a21c953248bcdfc1dd48988aad98efac870661d
            container_id = re.search('[a-z0-9]{64}', result).group(0)
            container = self.client.containers.get(container_id)
            self.run_vulnerable_container(container, port)
            self.create_nginx_config(container_name, port)
            keepalive_containers[container.name] = datetime.datetime.now()
            app.logger.info(f'challenge container created for {container_name}')
        except (docker.errors.BuildError, docker.errors.APIError) as e:
            app.logger.error(f'container build failed for {container_name}: {e}')
        except Exception as e:
            app.logger.error(f'unknown error while building container for {container_name}: {e}')
        self.lock.release()

    def remove_instance(self, container_name):
        try:
            os.remove(f'/etc/nginx/sites-enabled/containers/{container_name}.conf')
            app.logger.info(f'removed nginx config for {container_name}')
        except OSError as e:
            app.logger.error(f'failed to remove instance: {e}')

        try:
            container = self.client.containers.get(container_name)
            container.stop()
            # This try-except block and while loop below is required, because the
            # stop function from Docker SDK sometimes returns even when container 
            # still exist, what caused some conflicts while reverting container.
            # If container doesn't exists get function will throw 404 not found
            # error, which will be caught, by except block. Otherwise thread will
            # sleep for 1 second and try to get container again.
            try:
                while self.client.containers.get(container_name):
                    time.sleep(0.25)
            except Exception:
                pass

            if container.name in self.solved_challenges:
                self.solved_challenges.remove(container.name)
            app.logger.info(f'stopped container for {container_name}')
        except docker.errors.APIError as e:
            app.logger.error(f'failed to remove instance: {e}')
            app.logger.warning(f'container {container_name} might need manual removal')


    def build_challenge(self):
        # first element in the returned tuple from build function is Image object
        path = './containers/runc/vulnerable_container/'
        image = self.client.images.build(tag='runc_vuln', path=path)[0].save()
        with open('./containers/runc/runc_vuln.tar', 'wb') as f:
            for chunk in image:
                f.write(chunk)
        self.client.images.build(tag='runc_vuln_host', path='./containers/runc/')
        app.logger.info('runc challenge image successfully built')

    def create_nginx_config(self, container_name, port):
        config =  'location /challenges/runc/%s/ {\n' % container_name
        config += '    proxy_pass http://127.0.0.1:%s/;\n' % port
        config += '    proxy_http_version 1.1;\n'
        config += '    proxy_set_header X-Real-IP $remote_addr;\n'
        config += '    proxy_set_header Upgrade $http_upgrade;\n'
        config += '    proxy_set_header Connection "Upgrade";\n'
        config += '}\n'

        config_path = f'/etc/nginx/sites-enabled/containers/{container_name}.conf'
        try:
            with open(config_path, 'w+') as f:
                f.write(config)
        except OSError:
            raise Exception('nginx config file open failed')

        res = subprocess.call(['/usr/sbin/nginx', '-s', 'reload'])
        if res != 0:
            raise Exception('nginx reload failed (non zero exit code)')
        app.logger.info(f'nginx config created and reloaded for {container_name}')

    def run_vulnerable_container(self, container, port):
        # check if docker is running
        docker_soc_check = '''sh -c 'test -e /run/user/1000/docker.sock && echo -n "1" || echo -n "0"' '''

        while container.exec_run(docker_soc_check)[1].decode('utf-8') != '1':
            time.sleep(0.25)

        load_result = container.exec_run('docker load --input /opt/runc_vuln.tar')
        if load_result[0] != 0:  # check if command exit code is 0
            raise Exception(f'internal container build failed:\n{load_result[1].decode("utf-8")}')

        container_id = load_result[1].decode('utf-8').strip().split(':')[2]
        tag_result = container.exec_run(f'docker tag {container_id} vuln')
        if tag_result[0] != 0:
            raise Exception(f'internal container tag failed:\n{tag_result[1].decode("utf-8")}')

        run_result = container.exec_run(f'docker run -p {port}:8081 -d --restart unless-stopped vuln')
        if run_result[0] != 0:  # check if command exit code is 0
            raise Exception(f'internal container run failed:\n{run_result[1].decode("utf-8")}')

        app.logger.info(f'internal container created for {container.name}')
        try:
            # docker '--cpus' option in not avaliable in python SDK, but options below are equal to '--cpus=0.25'
            container.update(cpu_period=100000, cpu_quota=25000)
        except docker.errors.APIError:
            app.logger.critical(f'failed to enforce CPU limits on {container.name}, removing container')
            container.stop()

    def win_check(self):
        while True:
            time.sleep(1)
            for container in self.client.containers.list():
                try:
                    self.check_runc_checksum(container)
                except (docker.errors.NotFound, docker.errors.APIError):
                    continue
                except Exception as e:
                    app.logger.error(f'win check failed on {container.name} with error:\n{e}')

    def check_runc_checksum(self, container):
        if container.name.split('-')[0] == 'runc' and container.status == 'running':
            checksum = container.exec_run('/usr/bin/sha1sum /usr/local/bin/runc')[1].decode('utf-8').strip()
            if checksum != '52ad938ef4044df50d5176e4f6f44079a86f0110  /usr/local/bin/runc':
                if container.name not in self.solved_challenges:
                    app.logger.info(f'we got a win: {container.name}')
                    self.solved_challenges.append(container.name)

    def trigger(self):
        while True:
            time.sleep(60)
            app.logger.info('trying to trigger exploit for runc challenge')
            for container in self.client.containers.list():
                try:
                    self.exec_sh(container)
                except (docker.errors.NotFound, docker.errors.APIError):
                    continue
                except Exception as e:
                    app.logger.error(f'win check failed on {container.name} with error:\n{e}')

    def exec_sh(self, container):
        if container.name.split('-')[0] == 'runc' and container.status == 'running':
            internal_container = container.exec_run('docker ps')[1].decode('utf-8').split('\n')[1].split(' ')[0]
            container.exec_run(f'docker exec {internal_container} sh')
