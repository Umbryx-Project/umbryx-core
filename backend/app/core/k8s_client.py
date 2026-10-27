import json
import os
import subprocess
import tempfile
from pathlib import Path

from ..core.logging_setup import get_logger

logger = get_logger(__name__)

KUBECONFIG_PATH = os.environ.get("KUBECONFIG_PATH", "")
KUBECTL_TIMEOUT = int(os.environ.get("KUBECTL_TIMEOUT", "60"))


def _run(
    cmd: str,
    input_data: str | None = None,
    kubeconfig: str | None = None,
    check: bool = True,
    timeout: int | None = None,
):
    kc_file = None
    kc_path = kubeconfig or KUBECONFIG_PATH or None
    if kubeconfig and not os.path.isfile(kubeconfig):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".kubeconfig", delete=False)
        f.write(kubeconfig)
        f.close()
        kc_file = f.name
        kc_path = kc_file
    try:
        kc_args = []
        if kc_path:
            kc_args = ["--kubeconfig", kc_path]
        full_cmd = cmd.split() + kc_args if "kubectl" in cmd else cmd.split()
        r = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout or KUBECTL_TIMEOUT,
            input=input_data,
        )
        if check and r.returncode != 0:
            raise RuntimeError(
                f"kubectl failed (rc={r.returncode}): {r.stderr.strip() or r.stdout.strip()}"
            )
        return r.stdout
    finally:
        if kc_file:
            try:
                os.unlink(kc_file)
            except OSError:
                pass


def _kubectl_base() -> list[str]:
    cmd = ["kubectl"]
    if KUBECONFIG_PATH and Path(KUBECONFIG_PATH).exists():
        cmd += ["--kubeconfig", KUBECONFIG_PATH]
    return cmd


def _run_kubectl(
    args: list[str], stdin_data: str | None = None, timeout: int | None = None
) -> dict:
    cmd = _kubectl_base() + args
    t = timeout or KUBECTL_TIMEOUT
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=t,
            input=stdin_data,
        )
        return {"rc": r.returncode, "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": f"kubectl timed out after {t}s"}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": "kubectl not found in PATH"}


def k8s_apply(manifest: dict, namespace: str) -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        json.dump(manifest, f)
        f.flush()
        path = f.name
    try:
        r = _run_kubectl(["apply", "-f", path, "-n", namespace])
        if r["rc"] != 0:
            logger.error(f"k8s apply failed: {r['stderr']}")
        return r
    finally:
        os.unlink(path)


def k8s_apply_multi(manifests: list[dict], namespace: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        for m in manifests:
            f.write("---\n")
            json.dump(m, f)
            f.write("\n")
        f.flush()
        path = f.name
    try:
        r = _run_kubectl(["apply", "-f", path, "-n", namespace])
        if r["rc"] != 0:
            logger.error(f"k8s apply multi failed: {r['stderr']}")
        return [r]
    finally:
        os.unlink(path)


def k8s_delete(label_selector: str, namespace: str, kind: str = "all") -> dict:
    r = _run_kubectl(
        ["delete", kind, "-l", label_selector, "-n", namespace, "--ignore-not-found=true"]
    )
    return r


def k8s_patch_configmap(name: str, namespace: str, data: dict) -> dict:
    patch = {
        "data": {
            k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in data.items()
        }
    }
    patch_json = json.dumps(patch)
    r = _run_kubectl(
        ["patch", "configmap", name, "-n", namespace, "--type", "merge", "-p", patch_json]
    )
    if r["rc"] != 0:
        logger.error(f"k8s patch configmap failed: {r['stderr']}")
    return r


def k8s_rollout_restart(deployment: str, namespace: str) -> dict:
    r = _run_kubectl(["rollout", "restart", f"deployment/{deployment}", "-n", namespace])
    if r["rc"] != 0:
        logger.error(f"k8s rollout restart failed: {r['stderr']}")
    return r


def k8s_get_deployment_status(name: str, namespace: str) -> dict:
    r = _run_kubectl(["get", "deployment", name, "-n", namespace, "-o", "json"])
    if r["rc"] != 0:
        return {"status": "error", "error": r["stderr"]}
    try:
        d = json.loads(r["stdout"])
        conditions = d.get("status", {}).get("conditions", [])
        replicas = d.get("status", {}).get("replicas", 0)
        ready = d.get("status", {}).get("readyReplicas", 0)
        available = d.get("status", {}).get("availableReplicas", 0)
        return {
            "status": "running" if available > 0 else "pending",
            "replicas": replicas,
            "ready": ready,
            "available": available,
            "conditions": conditions,
        }
    except json.JSONDecodeError:
        return {"status": "error", "error": "failed to parse deployment status"}


def k8s_get_pod_logs(name: str, namespace: str, tail: int = 50) -> str:
    r = _run_kubectl(["logs", f"deployment/{name}", "-n", namespace, f"--tail={tail}"])
    return r.get("stdout", "") if r["rc"] == 0 else r.get("stderr", "")


def _get_k8s_node_ip() -> str | None:
    r = _run_kubectl(
        [
            "get",
            "nodes",
            "-o",
            "jsonpath={.items[0].status.addresses[?(@.type=='ExternalIP')].address}",
        ]
    )
    if r["rc"] == 0 and r["stdout"].strip():
        return r["stdout"].strip()
    r = _run_kubectl(
        [
            "get",
            "nodes",
            "-o",
            "jsonpath={.items[0].status.addresses[?(@.type=='InternalIP')].address}",
        ]
    )
    if r["rc"] == 0 and r["stdout"].strip():
        return r["stdout"].strip()
    return None


def k8s_get_service_url(name: str, namespace: str) -> str | None:
    r = _run_kubectl(["get", "svc", name, "-n", namespace, "-o", "json"])
    if r["rc"] != 0:
        return None
    try:
        svc = json.loads(r["stdout"])
        spec = svc.get("spec", {})
        p = spec.get("ports", [{}])[0]
        port = p.get("nodePort") or p.get("port", 80)
        if spec.get("type") == "LoadBalancer":
            ingress = (svc.get("status", {}).get("loadBalancer", {}).get("ingress") or [{}])[0]
            host = ingress.get("hostname") or ingress.get("ip", "")
            return f"http://{host}:{port}" if host else None
        if spec.get("type") == "NodePort":
            node_ip = _get_k8s_node_ip()
            return f"http://{node_ip}:{port}" if node_ip else f"http://localhost:{port}"
        cluster_ip = spec.get("clusterIP", "")
        return f"http://{cluster_ip}:{port}" if cluster_ip and cluster_ip != "None" else None
    except (json.JSONDecodeError, IndexError, KeyError):
        return None


def k8s_namespace_exists(namespace: str) -> bool:
    r = _run_kubectl(["get", "namespace", namespace, "-o", "name"])
    return r["rc"] == 0


def k8s_create_namespace(namespace: str) -> dict:
    manifest = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}}
    return k8s_apply(manifest, "default")
