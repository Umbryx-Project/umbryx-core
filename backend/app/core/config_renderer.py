import json
import re
import secrets
import string

from .logging_setup import get_logger

logger = get_logger(__name__)

_VAR_RE = re.compile(r"\{\{(\s*\w+(?:\|\w+(?::\w+)?)?\s*)\}\}")


def _gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _gen_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def render_config(template: dict | list | str, variables: dict) -> dict | list | str:
    if isinstance(template, str):
        return _render_string(template, variables)
    if isinstance(template, list):
        return [render_config(item, variables) for item in template]
    if isinstance(template, dict):
        return {k: render_config(v, variables) for k, v in template.items()}
    return template


def _render_string(s: str, variables: dict) -> str:
    def _replace(m):
        expr = m.group(1).strip()
        parts = expr.split("|")
        var_name = parts[0].strip()
        value = variables.get(var_name)
        if value is None:
            for fallback in parts[1:]:
                fb = fallback.strip()
                if fb.startswith("default:"):
                    return fb[len("default:") :]
                if fb == "generate_password":
                    return _gen_password()
                if fb == "generate_token":
                    return _gen_token()
            return m.group(0)
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

    return _VAR_RE.sub(_replace, s)


def build_instance_config(
    config_template: dict,
    project_vars: dict,
    users: list[dict],
    instance_vars: dict,
    existing_secrets: dict | None = None,
) -> dict:
    variables = {
        **project_vars,
        **instance_vars,
        "users_json": users,
        "users_yaml": _users_to_yaml(users),
        "user_count": len(users),
    }
    variables.setdefault("log_level", "info")
    if existing_secrets:
        for k, v in existing_secrets.items():
            variables.setdefault(k, v)
    return render_config(config_template, variables)


def build_manifest(template_manifest: dict, namespace: str, name: str, labels: dict) -> dict:
    manifest = json.loads(json.dumps(template_manifest))
    metadata = manifest.setdefault("metadata", {})
    metadata["name"] = name
    metadata.setdefault("namespace", namespace)
    existing_labels = metadata.setdefault("labels", {})
    existing_labels.update(labels)
    spec = manifest.get("spec", {})
    if "selector" in spec:
        sel = spec["selector"]
        if "matchLabels" in sel:
            sel["matchLabels"].update(labels)
    template_spec = spec.get("template", {}).get("spec", {})
    pod_metadata = spec.get("template", {}).get("metadata", {})
    pod_labels = pod_metadata.setdefault("labels", {})
    pod_labels.update(labels)
    for container in template_spec.get("containers", []):
        for env in container.get("envFrom", []):
            cfg_ref = env.get("configMapRef")
            if cfg_ref:
                cfg_ref["name"] = f"{name}-config"
    return manifest


def build_configmap_manifest(name: str, namespace: str, data: dict, labels: dict) -> dict:
    stringified = {}
    for k, v in data.items():
        stringified[k] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": f"{name}-config", "namespace": namespace, "labels": labels},
        "data": stringified,
    }


def build_service_manifest(
    name: str, namespace: str, ports: list[dict], labels: dict, service_type: str = "ClusterIP"
) -> dict:
    sp = []
    for p in ports:
        sp.append(
            {
                "name": p.get("name", "http"),
                "port": p.get("servicePort", p.get("containerPort", 80)),
                "targetPort": p.get("containerPort", 80),
            }
        )
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {"selector": labels, "type": service_type, "ports": sp},
    }


def build_pvc_manifest(name: str, namespace: str, size: str, labels: dict) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": f"{name}-data", "namespace": namespace, "labels": labels},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": size}},
        },
    }


def _users_to_yaml(users: list[dict]) -> str:
    lines = []
    for u in users:
        un = u.get("username", "").replace('"', '\\"').replace("\n", "\\n")
        lines.append(f'  - username: "{un}"')
        if u.get("password"):
            pw = str(u["password"]).replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'    password: "{pw}"')
        if u.get("role"):
            rl = str(u["role"]).replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'    role: "{rl}"')
    return "\n".join(lines)
