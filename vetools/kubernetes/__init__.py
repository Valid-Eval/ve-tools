import subprocess
import shlex
import os
import sys
import time
import socket
from contextlib import closing

from kubernetes.client.rest import ApiException

def get_a_pod(v1, context, pod_name_filter):
    results = v1.list_namespaced_pod(namespace=context['namespace'])
    for item in results.items:
        if item.metadata.name.startswith(pod_name_filter):
            try:
                resp = v1.read_namespaced_pod(
                    name=item.metadata.name,
                    namespace=context['namespace'])
                return resp
            except ApiException as e:
                if e.status != 404:
                    sys.stderr.write(f"Unknown error: {e}\n")
                    sys.exit(1)



def open_port_forward(pod, from_port, to_port, to_parent, to_child):
    cmd = f"kubectl port-forward {pod.metadata.name} {from_port}:{to_port} -n {pod.metadata.namespace}" 
    proc = subprocess.Popen(shlex.split(cmd),
        env=os.environ, stdout=subprocess.PIPE
    )
    os.set_blocking(proc.stdout.fileno(), False)
    while True:
        if(proc.stdout.peek(1)):
            line = proc.stdout.readline()
            to_parent.put(line.decode("utf-8"))
        if not to_child.empty():
            data = to_child.get()
            if "exit" in data:
                break
        time.sleep(0.1)
    proc.kill()


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]
