import subprocess
import threading
import datetime
import docker
import time
import os

from challenges.challenge import Challenge
from main import app
import utils


class Privileged(Challenge):

    def __init__(self, client, solved_challenges):
        self.client = client
        self.solved_challenges = solved_challenges
        self.lock = threading.Lock()
        threading.Thread(target=self.trigger).start()

    @property
    def title(self):
        return 'Privileged'

    @property
    def subtitle(self):
        return '+ cgroup "notification on release" feature'

    @property
    def description(self):
        return '''Challenge is about launching a process on the host from within 
               a Docker container run with the --privileged flag. This is achieved by 
                  abusing the Linux cgroup v1 “notification on release” feature.'''

    def run_instance(self, container_name, keepalive_containers):
        self.lock.acquire()
        port = utils.get_free_port()

        if port == -1:
            raise Exception("failed to run instance, couldn't find available port")

        try:
            container = self.client.containers.run(
                ports={f'{port}/tcp': f'{port}/tcp'},
                privileged=True,
                remove=True,
                name=container_name,
                detach=True,
                image='privileged_vuln_host',
                mem_limit='64m',
                memswap_limit='64m',
                read_only=False,
                cpu_period=100000,
                cpu_quota=25000
            )
            self.run_vulnerable_container(container, port)
            self.create_nginx_config(container_name, port)
            keepalive_containers[container.name] = datetime.datetime.now()
            app.logger.info(f'challenge container created for {container_name}')
        except (docker.errors.BuildError, docker.errors.APIError) as e:
            app.logger.error(f'container build failed for {container_name}: {e}')
        except Exception as e:
            app.logger.error(f'unknown error while building container for {container_name}: {e}')
        self.lock.release()
        threading.Thread(target=self.win_check).start()

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
            # sleep for 1 second and try to get container again
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
        path = './containers/privileged/vulnerable_container/'
        image = self.client.images.build(tag='privileged_vuln', path=path)[0].save()
        with open('./containers/privileged/privileged_vuln.tar', 'wb') as f:
            for chunk in image:
                f.write(chunk)
        self.client.images.build(tag='privileged_vuln_host', path='./containers/privileged/')
        app.logger.info('privileged challenge image successfully builded')

    def create_nginx_config(self, container_name, port):
        config =  'location /challenges/privileged/%s/ {\n' % container_name
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
        docker_soc_check = '''sh -c 'test -e /var/run/docker.sock && echo -n "1" || echo -n "0"' '''

        while container.exec_run(docker_soc_check)[1].decode('utf-8') != '1':
            time.sleep(0.25)

        load_result = container.exec_run('docker load --input /opt/privileged_vuln.tar')
        if load_result[0] != 0:  # check if command exit code is 0
            raise Exception(f'internal container build failed:\n{load_result[1].decode("utf-8")}')

        container_id = load_result[1].decode('utf-8').strip().split(':')[2]
        tag_result = container.exec_run(f'docker tag {container_id} vuln')
        if tag_result[0] != 0:
            raise Exception(f'internal container tag failed:\n{tag_result[1].decode("utf-8")}')

        run_result = container.exec_run(f'docker run -p {port}:8081 -d --restart unless-stopped -it --name inside --privileged vuln')
        if run_result[0] != 0:  # check if command exit code is 0
            raise Exception(f'internal container run failed:\n{run_result[1].decode("utf-8")}')

        app.logger.info(f'internal container created for {container.name}')

    def win_check(self):
        while True:
            time.sleep(1)
            for container in self.client.containers.list():
                try:
                    if container.name.split('-')[0] == 'privileged' and container.status == 'running':
                        ch = container.exec_run(f'docker exec inside cat /sys/fs/cgroup/rdma/release_agent')[1]
                        ch = ch.decode('utf-8')

                        ch2 = container.exec_run('cat ' + ch)[1].decode('utf-8')
                        ch3=container.exec_run(ch)[1].decode('utf-8')
                        container.exec_run('>' + ch)[1]

                        if '/bin/sh' in ch2 and 'ps' in ch2 and 'failed' not in ch3:
                            if container.name not in self.solved_challenges:
                                app.logger.info(f'we got a win: {container.name}')
                                self.solved_challenges.append(container.name)
                except (docker.errors.NotFound, docker.errors.APIError):
                    continue
                except Exception as e:
                    app.logger.error(f'win check failed on {container.name} with error:\n{e}')

    def trigger(self):
        while True:
            time.sleep(60)
            app.logger.info('trying to trigger exploit for privileged challenge')
            for container in self.client.containers.list():
                try:
                    if container.name.split('-')[0] == 'privileged' and container.status == 'running':
                        internal_container = container.exec_run('docker ps')[1].decode('utf-8').split('\n')[1].split(' ')[0]
                        container.exec_run(f'docker exec {internal_container} sh')
                except (docker.errors.NotFound, docker.errors.APIError):
                    continue
                except Exception as e:
                    app.logger.error(f'win check failed on {container.name} with error:\n{e}')
