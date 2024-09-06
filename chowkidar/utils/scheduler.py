import docker 
from datetime import datetime, timezone
import pdfkit
from chowkidar import get_workers, task_queue
import requests
import os




workers = int(get_workers())
client = docker.DockerClient(base_url="unix://var/run/docker.sock")


def run_scan(secret_key, scan_result_api, add_vulnerability_api, scan_status_api, audit):
    running_containers = client.containers.list(filters={'status': 'running'})
    previous_tasks = [container for container in running_containers if  container.name not in ['chowkidar-nginx-1', 'chowkidar-chowkidar-1', 'chowkidar-db-1', 'chowkidar-scheduler-1', 'chowkidar-certbot-1']]
    if len(previous_tasks) >= workers:
        for task in previous_tasks:
            task.wait()
    if 'web' in audit.asset_type:
        tools = eval(audit.tools)
        command=f"python3 scanner.py {secret_key} {scan_result_api} {add_vulnerability_api} {scan_status_api} {audit.id} {audit.url} {tools['nmap']} {tools['headers']} {tools['dirsearch']} {tools['testssl']} {tools['nuclei']} {tools['sublister']} {tools['wpscan']} {audit.Auditor.wpscan_api}"
        container = client.containers.run("web-scanner", 
                                        name=f"web-{audit.name}-{datetime.now(timezone.utc).strftime('%d-%m-%Y-%H-%M-%S')}", 
                                        command=command, 
                                        network="host", 
                                        cap_add=['NET_RAW', 'NET_ADMIN', 'NET_BIND_SERVICE'],
                                        detach=True)
    elif 'cloud' in audit.asset_type:
        command = f'python3 scanner.py {secret_key} {scan_result_api} {add_vulnerability_api} {scan_status_api} {audit.id} {audit.asset_type} {audit.access_id} {audit.secret_key} "{audit.regions}" "{audit.services}"'
        container = client.containers.run("cloud-scanner", 
                                        name=f"cloud-{audit.name}-{datetime.now(timezone.utc).strftime('%d-%m-%Y-%H-%M-%S')}", 
                                        command=command, 
                                        network="host", 
                                        cap_add=['NET_RAW', 'NET_ADMIN', 'NET_BIND_SERVICE'],
                                        detach=True)
    data = {'secret_key':os.environ['SCANNER_SECRET_KEY'],
            'audit_id':audit.id,
            'container_id':container.id}
    response = requests.post(f'{os.getenv('SERVER_URL')}:5000/audits/containerid', json=data)
    return container.id




def remove_task(job_id):
    job = task_queue.fetch_job(job_id)
    if job and job.get_status() != 'finished':
        try:
            job.cancel()
            return True
        except:
            return False
    return False




def delete_container(container_id):
    try:
        container = client.containers.get(container_id)
        container.remove(force=True)
        return True
    except:
        return False




def generate_report(content):
    options = {
                'page-size': 'A4',
                'margin-top': '0in',
                'margin-right': '0in',
                'margin-bottom': '0.5in',
                'margin-left': '0in',
                'encoding': "UTF-8",
                }
    pdf = pdfkit.from_string(content, options=options)
    return pdf

