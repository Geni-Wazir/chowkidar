import docker 
from datetime import datetime, timezone
from chowkidar.models import User, Audit, VulnerabilityDiscovered, VulnerabilityTemplates, db
from flask import render_template, url_for
import pdfkit
from chowkidar import get_workers, task_queue
import requests
import os




workers = int(get_workers())

client = docker.DockerClient(base_url="unix://var/run/docker.sock")

def run_scan(secret_key, scan_result_api, add_vulnerability_api, scan_status_api, audit):
    # Get a list of running containers
    running_containers = client.containers.list(filters={'status': 'running'})
    previous_tasks = [container for container in running_containers if  container.name not in ['chowkidar-nginx-1', 'chowkidar-chowkidar-1', 'chowkidar-db-1', 'chowkidar-scheduler-1']]
    # If there are running containers with the same name pattern, wait for them to finish
    if len(previous_tasks) >= workers:
        print(f"Waiting for previous tasks ({', '.join([task.name for task in previous_tasks])}) to finish...")
        for task in previous_tasks:
            task.wait()
    # Start a new container
    command="python3 scanner.py {} {} {} {} {} {} {} {} {} {} {} {} {} {}".format(
                                                                        secret_key,
                                                                        scan_result_api, 
                                                                        add_vulnerability_api,
                                                                        scan_status_api, 
                                                                        audit.id, 
                                                                        audit.url, 
                                                                        audit.nmap, 
                                                                        audit.headers, 
                                                                        audit.dirsearch, 
                                                                        audit.testssl, 
                                                                        audit.nuclei, 
                                                                        audit.sublister, 
                                                                        audit.wpscan,
                                                                        audit.Auditor.wpscan_api
                                                                        )
    container = client.containers.run("scanner", name=f"{audit.name}-{datetime.now(timezone.utc).strftime('%d-%m-%Y-%H-%M-%S')}", command=command, network="host", detach=True)
    data = {'secret_key':os.environ['SCANNER_SECRET_KEY'],
            'audit_id':audit.id,
            'container_id':container.id}
    response = requests.post('http://localhost:5000/audits/containerid', json=data)
    return container.id



def remove_task(job_id):
    job = task_queue.fetch_job(job_id)
    if job is not None:
        if job.get_status() != 'finished':
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
                'margin-bottom': '0in',
                'margin-left': '0in',
                'encoding': "UTF-8",
                }
    pdf = pdfkit.from_string(content, options=options)
    return pdf

