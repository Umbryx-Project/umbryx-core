import json
import os
import subprocess
import tempfile

from sqlalchemy.orm import Session

from ..core.events import log_event
from ..core.logging_setup import get_logger
from ..models.instance_pool import InstanceCredential, InstanceTemplate, ManagedInstance
from ..models.project import ProjectMember
from .config_renderer import (
    build_configmap_manifest,
    build_instance_config,
    build_manifest,
    build_pvc_manifest,
    build_service_manifest,
)
from .k8s_client import (
    k8s_apply_multi,
    k8s_create_namespace,
    k8s_get_deployment_status,
    k8s_get_service_url,
    k8s_namespace_exists,
    k8s_patch_configmap,
    k8s_rollout_restart,
)
from .utils import new_id, ts_now

logger = get_logger(__name__)

_DEFAULT_REGISTRY = os.environ.get("REGISTRY_URL", "http://registry:5000")
_EXTERNAL_REGISTRY = os.environ.get("REGISTRY_EXTERNAL_URL", "")


def _run(cmd, timeout=600, input=None, check=True):
    if input and isinstance(input, str):
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input.encode()
        )
    else:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={r.returncode}): {r.stderr.strip() or r.stdout.strip()}"
        )
    return r


def _extract_image(manifest: dict) -> str | None:
    containers = manifest.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    if containers:
        return containers[0].get("image")
    return None


def _delivery_registry(template: InstanceTemplate) -> str:
    image = _extract_image(template.manifest) or ""
    registry = template.image_registry or _EXTERNAL_REGISTRY or _DEFAULT_REGISTRY
    clean = registry.replace("http://", "").replace("https://", "").rstrip("/")
    tagged = f"{clean}/{image}"
    try:
        reg_user = os.environ.get("REGISTRY_USER", "")
        reg_pass = os.environ.get("REGISTRY_PASS", "")
        if reg_user and reg_pass:
            p = subprocess.run(
                ["docker", "login", clean, "-u", reg_user, "-p", reg_pass],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if p.returncode != 0:
                logger.warning(f"Registry login failed: {p.stderr.strip()}")
        _run(["docker", "tag", image, tagged], 120)
        _run(["docker", "push", tagged], 600)
        logger.info(f"Registry push: {image} -> {tagged}")
        return tagged
    except Exception as e:
        logger.error(f"Registry push failed: {e}")
        return image


def _delivery_k8s_direct(template: InstanceTemplate) -> str:
    image = _extract_image(template.manifest) or ""
    if not image:
        return ""
    try:
        kubeconfig = os.environ.get("KUBECONFIG_PATH", "")
        kubectl = ["kubectl"]
        if kubeconfig:
            kubectl += ["--kubeconfig", kubeconfig]

        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
            tar_path = f.name
        _run(["docker", "save", "-o", tar_path, image], 600)

        nodes_raw = _run(kubectl + ["get", "nodes", "-o", "name"], 60)
        nodes = [
            n.strip().replace("node/", "")
            for n in nodes_raw.stdout.strip().split("\n")
            if n.strip()
        ]
        if not nodes:
            logger.error("No K8s nodes found")
            os.unlink(tar_path)
            return image

        for node in nodes:
            pod = f"img-ld-{os.getpid()}"
            ns = "umbryx-system"
            _run(kubectl + ["create", "namespace", ns, "--dry-run=client", "-o", "yaml"], 10)

            _run(
                kubectl
                + [
                    "run",
                    pod,
                    "--image=alpine",
                    "--restart=Never",
                    "-n",
                    ns,
                    "--overrides",
                    json.dumps(
                        {
                            "spec": {
                                "nodeName": node,
                                "containers": [
                                    {
                                        "name": "loader",
                                        "image": "alpine",
                                        "command": ["sleep", "600"],
                                        "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                                        "securityContext": {"privileged": True},
                                    }
                                ],
                                "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                                "tolerations": [{"operator": "Exists"}],
                            },
                        }
                    ),
                ],
                30,
            )
            _run(
                kubectl
                + ["wait", f"pod/{pod}", "-n", ns, "--for=condition=Ready", "--timeout=90s"],
                100,
            )

            _run(kubectl + ["cp", tar_path, f"{ns}/{pod}:/tmp/image.tar"], 300)
            _run(
                kubectl
                + ["exec", pod, "-n", ns, "--", "cp", "/tmp/image.tar", "/host/tmp/umbryx-img.tar"],
                30,
            )
            _run(
                kubectl
                + [
                    "exec",
                    pod,
                    "-n",
                    ns,
                    "--",
                    "chroot",
                    "/host",
                    "ctr",
                    "-n",
                    "k8s.io",
                    "images",
                    "import",
                    "/tmp/umbryx-img.tar",
                ],
                120,
            )
            _run(
                kubectl
                + [
                    "exec",
                    pod,
                    "-n",
                    ns,
                    "--",
                    "chroot",
                    "/host",
                    "rm",
                    "-f",
                    "/tmp/umbryx-img.tar",
                ],
                10,
            )
            _run(kubectl + ["delete", "pod", pod, "-n", ns, "--force"], 15)
            logger.info(f"K8s direct: imported {image} on node {node}")

        os.unlink(tar_path)
        return image
    except Exception as e:
        logger.error(f"K8s direct delivery failed: {e}")
        return image


def _delivery_ssh_direct(template: InstanceTemplate) -> str:
    image = _extract_image(template.manifest) or ""
    host = template.ssh_host
    if not image or not host:
        return image
    if any(c in host for c in " \t\n;|&$`()!") or host.startswith("-"):
        logger.error(f"Invalid ssh_host: {host}")
        return image
    try:
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
            tar_path = f.name
        _run(["docker", "save", "-o", tar_path, image], 600)
        _run(["scp", tar_path, f"{host}:/tmp/umbryx-image.tar"], 300)
        _run(["ssh", host, "docker load -i /tmp/umbryx-image.tar && rm /tmp/umbryx-image.tar"], 300)
        os.unlink(tar_path)
        logger.info(f"SSH direct: loaded {image} on {host}")
        return image
    except Exception as e:
        logger.error(f"SSH direct delivery failed: {e}")
        return image


def ensure_image_pushed(template: InstanceTemplate) -> str:
    image = _extract_image(template.manifest)
    if not image:
        return ""
    mode = getattr(template, "image_delivery", "registry") or "registry"
    if mode == "k8s-direct":
        return _delivery_k8s_direct(template)
    if mode == "ssh-direct":
        return _delivery_ssh_direct(template)
    return _delivery_registry(template)


def provision_instances(
    db: Session, template_id: str, count: int, created_by: str | None = None
) -> list[ManagedInstance]:
    template = db.query(InstanceTemplate).get(template_id)
    if not template:
        raise ValueError(f"Template {template_id} not found")

    created = []
    pushed_image = ensure_image_pushed(template)

    for _i in range(count):
        instance_id = new_id("mi")
        suffix = instance_id[-6:]
        ns = f"umbryx-{suffix}"
        deploy_name = f"{template.service_type}-{suffix}"

        instance = ManagedInstance(
            id=instance_id,
            template_id=template.id,
            status="provisioning",
            project_id=None,
            namespace=ns,
            deployment_name=deploy_name,
            configmap_name=f"{deploy_name}-config",
            service_name=deploy_name,
            config_current={},
            config_version=0,
            vars={},
            ts=ts_now(),
        )
        db.add(instance)
        db.flush()

        try:
            _deploy_to_k8s(template, instance, pushed_image)
            instance.status = "standby"
            log_event(
                db, "", created_by, "instance", "provision", f"{template.name} → {instance.id}"
            )
        except Exception as e:
            logger.error(f"Failed to provision {instance_id}: {e}")
            instance.status = "error"
            instance.error_msg = str(e)

        created.append(instance)

    db.commit()
    return created


def _deploy_to_k8s(
    template: InstanceTemplate, instance: ManagedInstance, image_override: str | None = None
):
    labels = {"app.umbryx/instance": instance.id, "app.umbryx/service": template.service_type}

    if not k8s_namespace_exists(instance.namespace):
        k8s_create_namespace(instance.namespace)

    manifest_data = json.loads(json.dumps(template.manifest))
    if image_override:
        containers = (
            manifest_data.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        )
        for c in containers:
            if "image" in c:
                c["image"] = image_override

    manifests = []

    if manifest_data:
        rendered = build_manifest(
            manifest_data, instance.namespace, instance.deployment_name, labels
        )
        containers = (
            rendered.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        )
        for c in containers:
            vols = c.setdefault("volumeMounts", [])
            vols.append({"name": "data", "mountPath": "/data"})
            vols.append({"name": "config", "mountPath": "/config"})
        pod_spec = rendered.get("spec", {}).get("template", {}).get("spec", {})
        vols = pod_spec.setdefault("volumes", [])
        vols.append(
            {
                "name": "data",
                "persistentVolumeClaim": {"claimName": f"{instance.deployment_name}-data"},
            }
        )
        vols.append({"name": "config", "configMap": {"name": instance.configmap_name}})
        manifests.append(rendered)

    pvc_size = (template.resource_limits or {}).get("pvc_size", "1Gi")
    manifests.append(
        build_pvc_manifest(instance.deployment_name, instance.namespace, pvc_size, labels)
    )

    cm_data = render_default_config(template)
    manifests.append(
        build_configmap_manifest(instance.deployment_name, instance.namespace, cm_data, labels)
    )

    if template.ports:
        svc_type = (template.resource_limits or {}).get("service_type", "ClusterIP")
        manifests.append(
            build_service_manifest(
                instance.deployment_name, instance.namespace, template.ports, labels, svc_type
            )
        )

    k8s_apply_multi(manifests, instance.namespace)


def render_default_config(template: InstanceTemplate) -> dict:
    if not template.config_template:
        return {"placeholder": "no config template defined"}
    from .config_renderer import render_config

    return render_config(
        template.config_template, {"psk": "standby-mode", "users_json": [], "user_count": 0}
    )


def claim_instance(
    db: Session, instance_id: str, project_id: str, variables: dict | None = None
) -> ManagedInstance:
    instance = db.query(ManagedInstance).get(instance_id)
    if not instance:
        raise ValueError(f"Instance {instance_id} not found")
    if instance.status not in ("standby", "error"):
        raise ValueError(f"Instance {instance_id} is not available (status={instance.status})")

    instance.project_id = project_id
    instance.vars = variables or {}
    instance.claim_ts = ts_now()
    instance.status = "claimed"

    _reconfigure(db, instance)
    instance.status = "running"
    log_event(
        db,
        project_id,
        "",
        "instance",
        "claim",
        f"{instance.deployment_name} → project {project_id}",
    )
    db.commit()
    return instance


def release_instance(db: Session, instance_id: str) -> ManagedInstance:
    instance = db.query(ManagedInstance).get(instance_id)
    if not instance:
        raise ValueError(f"Instance {instance_id} not found")

    db.query(InstanceCredential).filter(InstanceCredential.instance_id == instance_id).update(
        {"status": "revoked"}
    )

    old_project_id = instance.project_id
    instance.project_id = None
    instance.vars = {}
    instance.claim_ts = None
    instance.host_id = None

    template = db.query(InstanceTemplate).get(instance.template_id)
    if template:
        default_config = render_default_config(template)
        k8s_patch_configmap(instance.configmap_name, instance.namespace, default_config)
        k8s_rollout_restart(instance.deployment_name, instance.namespace)
        instance.config_current = default_config
        instance.config_version += 1
        instance.last_reconfig_ts = ts_now()

    instance.status = "standby"
    log_event(
        db,
        old_project_id or "",
        "",
        "instance",
        "release",
        f"{instance.deployment_name} returned to pool",
    )
    db.commit()
    return instance


def reconfigure_instance(db: Session, instance_id: str) -> ManagedInstance:
    instance = db.query(ManagedInstance).get(instance_id)
    if not instance:
        raise ValueError(f"Instance {instance_id} not found")
    _reconfigure(db, instance)
    db.commit()
    return instance


def _reconfigure(db: Session, instance: ManagedInstance):
    template = db.query(InstanceTemplate).get(instance.template_id)
    if not template:
        raise ValueError(f"Template {instance.template_id} not found")

    users = _get_project_users(db, instance.project_id)
    project_vars = _get_project_vars(db, instance.project_id)

    existing_secrets = (
        _extract_secrets(instance.config_current) if instance.config_current else None
    )

    new_config = build_instance_config(
        template.config_template,
        project_vars,
        users,
        instance.vars,
        existing_secrets=existing_secrets,
    )

    k8s_patch_configmap(instance.configmap_name, instance.namespace, new_config)
    k8s_rollout_restart(instance.deployment_name, instance.namespace)

    instance.config_current = new_config
    instance.config_version += 1
    instance.last_reconfig_ts = ts_now()

    _sync_user_credentials(db, instance, template, users, new_config)


def _get_project_users(db: Session, project_id: str | None) -> list[dict]:
    if not project_id:
        return []
    from ..models.auth import User

    members = db.query(ProjectMember).filter(ProjectMember.pid == project_id).all()
    users = []
    for m in members:
        u = db.query(User).get(m.uid)
        if u:
            users.append({"username": u.username, "role": m.role, "user_id": u.id})
    return users


def _get_project_vars(db: Session, project_id: str | None) -> dict:
    if not project_id:
        return {}
    from ..models.host import Host

    hosts = db.query(Host).filter(Host.pid == project_id).all()
    return {
        "project_id": project_id,
        "hosts": [{"hostname": h.hostname, "ip": h.ip} for h in hosts if h.ip],
    }


def _extract_secrets(config, out: dict | None = None) -> dict:
    """Recursively collect CONFIG_SECRET_KEYS values anywhere in config —
    config_renderer.render_config() recurses into dicts/lists when
    rendering a template (e.g. a nested `env` block), so a secret placed
    there by a template is not guaranteed to sit at the top level of the
    resulting config_current. A top-level-only scan here means such a
    secret never gets a protected copy in InstanceCredential at all — the
    plaintext in config_current would be its only stored form (found in
    post-commit review of security audit finding F6)."""
    from ..schemas.instance_pool import CONFIG_SECRET_KEYS

    if out is None:
        out = {}
    if isinstance(config, dict):
        for k, v in config.items():
            if k in CONFIG_SECRET_KEYS and isinstance(v, str):
                out[k] = v
            else:
                _extract_secrets(v, out)
    elif isinstance(config, list):
        for item in config:
            _extract_secrets(item, out)
    return out


def _get_secret_from_config(config: dict, keys: list[str]) -> str | None:
    for k in keys:
        v = config.get(k)
        if v and isinstance(v, str):
            return v
    return None


def _sync_user_credentials(
    db: Session,
    instance: ManagedInstance,
    template: InstanceTemplate,
    users: list[dict],
    config: dict,
):
    if not instance.project_id:
        return

    from .config_renderer import _gen_password, _gen_token
    from .crypto import encrypt_str

    svc_url = k8s_get_service_url(instance.service_name, instance.namespace)
    ports = template.ports or [{}]
    default_port = ports[0].get("servicePort", ports[0].get("containerPort", 80)) if ports else 80

    existing = {
        c.user_id: c
        for c in db.query(InstanceCredential)
        .filter(
            InstanceCredential.instance_id == instance.id,
            InstanceCredential.status == "active",
        )
        .all()
    }

    shared_password = (
        _get_secret_from_config(
            config,
            [
                "MYTHIC_ADMIN_PASS",
                "COVENANT_PASS",
                "GOPHISH_ADMIN_PASS",
                "PASSWORD",
                "password",
                "admin_pass",
                "PSK",
                "psk",
                "AUTH",
                "auth",
            ],
        )
        or _gen_password()
    )
    shared_token = _get_secret_from_config(config, ["PSK", "psk", "token"]) or _gen_token()

    for u in users:
        uid = u.get("user_id")
        if not uid:
            continue
        cred = existing.pop(uid, None)
        if not cred:
            cred = InstanceCredential(
                id=new_id("ic"),
                instance_id=instance.id,
                project_id=instance.project_id,
                user_id=uid,
                service_type=template.service_type,
                service_name=template.name,
                username=u.get("username", ""),
                password=encrypt_str(shared_password),
                token=encrypt_str(shared_token),
                connection_url=svc_url,
                connection_port=default_port,
                protocol="https" if default_port in (443, 8443) else "http",
                status="active",
                ts=ts_now(),
            )
            db.add(cred)
        else:
            cred.connection_url = svc_url or cred.connection_url
            cred.connection_port = default_port

    for stale_cred in existing.values():
        stale_cred.status = "revoked"


def sync_project_users(db: Session, project_id: str):
    instances = (
        db.query(ManagedInstance)
        .filter(
            ManagedInstance.project_id == project_id,
            ManagedInstance.status == "running",
        )
        .all()
    )
    for inst in instances:
        try:
            _reconfigure(db, inst)
        except Exception as e:
            logger.error(f"Failed to reconfigure {inst.id}: {e}")
    db.commit()


def destroy_instance(db: Session, instance_id: str):
    instance = db.query(ManagedInstance).get(instance_id)
    if not instance:
        raise ValueError(f"Instance {instance_id} not found")

    db.query(InstanceCredential).filter(InstanceCredential.instance_id == instance_id).delete(
        synchronize_session=False
    )

    try:
        kubeconfig = os.environ.get("KUBECONFIG_PATH", "")
        kubectl = ["kubectl"]
        if kubeconfig:
            kubectl += ["--kubeconfig", kubeconfig]
        _run(kubectl + ["delete", "namespace", instance.namespace, "--ignore-not-found=true"], 60)
    except Exception as e:
        logger.warning(f"Namespace cleanup failed for {instance_id}: {e}")

    log_event(
        db,
        instance.project_id or "",
        "",
        "instance",
        "destroy",
        f"{instance.deployment_name} ({instance.namespace})",
    )
    db.delete(instance)
    db.commit()


def get_instance_status(db: Session, instance_id: str) -> dict:
    instance = db.query(ManagedInstance).get(instance_id)
    if not instance:
        raise ValueError(f"Instance {instance_id} not found")
    k8s_status = k8s_get_deployment_status(instance.deployment_name, instance.namespace)
    svc_url = k8s_get_service_url(instance.service_name, instance.namespace)
    return {
        "id": instance.id,
        "status": instance.status,
        "namespace": instance.namespace,
        "deployment": instance.deployment_name,
        "config_version": instance.config_version,
        "k8s": k8s_status,
        "service_url": svc_url,
    }


def get_user_credentials(
    db: Session, user_id: str, project_id: str | None = None
) -> list[InstanceCredential]:
    q = db.query(InstanceCredential).filter(
        InstanceCredential.user_id == user_id,
        InstanceCredential.status == "active",
    )
    if project_id:
        q = q.filter(InstanceCredential.project_id == project_id)
    return q.all()


def refill_pool(db: Session):
    templates = db.query(InstanceTemplate).filter(InstanceTemplate.min_pool_size > 0).all()
    for t in templates:
        standby = (
            db.query(ManagedInstance)
            .filter(
                ManagedInstance.template_id == t.id,
                ManagedInstance.status == "standby",
            )
            .count()
        )
        deficit = t.min_pool_size - standby
        if deficit > 0:
            logger.info(f"Pool refill: provisioning {deficit} instances of {t.name}")
            provision_instances(db, t.id, deficit)


_BUILTIN_POOL_TEMPLATES = [
    {
        "id": "pool-adaptix-c2",
        "name": "Adaptix C2",
        "service_type": "adaptix",
        "description": "Adaptix C2 framework — cross-platform command & control server with GUI client, Extension Kit BOFs, and axscripts pre-loaded",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "adaptix",
                                "image": "umbryx/adaptix:latest",
                                "args": ["-profile", "/data/profile.yaml"],
                                "ports": [{"containerPort": 8443}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "200m", "memory": "256Mi"},
                                    "limits": {"cpu": "1", "memory": "512Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "SERVER_HOST": "0.0.0.0",
            "SERVER_PORT": "8443",
            "PSK": "{{psk|generate_token}}",
            "LOG_LEVEL": "info",
        },
        "config_schema": {
            "SERVER_HOST": {"type": "string", "label": "Listen Host"},
            "SERVER_PORT": {"type": "string", "label": "Listen Port"},
            "PSK": {"type": "string", "label": "Pre-Shared Key", "auto": True},
            "LOG_LEVEL": {
                "type": "select",
                "label": "Log Level",
                "options": ["debug", "info", "warn", "error"],
            },
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "1", "memory": "512Mi"},
        "ports": [{"name": "https", "containerPort": 8443, "servicePort": 8443}],
        "health_check_path": "/api/health",
        "min_pool_size": 0,
        "image_delivery": "k8s-direct",
    },
    {
        "id": "pool-mythic-c2",
        "name": "Mythic C2",
        "service_type": "mythic",
        "description": "Mythic C2 platform — multi-agent command & control with web UI, containerized agents, and REST API",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "mythic",
                                "image": "umbryx/mythic:latest",
                                "command": ["/bin/bash", "-c"],
                                "args": ["mythic-cli start && tail -f /dev/null"],
                                "ports": [{"containerPort": 7443}, {"containerPort": 8080}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "500m", "memory": "512Mi"},
                                    "limits": {"cpu": "2", "memory": "2Gi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "MYTHIC_ADMIN_USER": "admin",
            "MYTHIC_ADMIN_PASS": "{{admin_pass|generate_password}}",
            "SERVER_PORT": "7443",
            "API_PORT": "8080",
            "PSK": "{{psk|generate_token}}",
        },
        "config_schema": {
            "MYTHIC_ADMIN_USER": {"type": "string", "label": "Admin Username"},
            "MYTHIC_ADMIN_PASS": {"type": "string", "label": "Admin Password", "auto": True},
            "SERVER_PORT": {"type": "string", "label": "Server Port"},
            "API_PORT": {"type": "string", "label": "API Port"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "2", "memory": "2Gi"},
        "ports": [
            {"name": "mythic-https", "containerPort": 7443, "servicePort": 7443},
            {"name": "mythic-api", "containerPort": 8080, "servicePort": 8080},
        ],
        "health_check_path": "/api/health",
        "min_pool_size": 0,
        "image_delivery": "k8s-direct",
    },
    {
        "id": "pool-sliver-c2",
        "name": "Sliver C2",
        "service_type": "sliver",
        "description": "Sliver C2 — implant framework with mTLS, WireGuard, DNS and HTTP(S) listeners, operator gRPC interface",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "sliver",
                                "image": "umbryx/sliver:latest",
                                "command": ["/opt/sliver/sliver-server"],
                                "args": ["daemon", "--lhost", "0.0.0.0"],
                                "ports": [
                                    {"containerPort": 31337},
                                    {"containerPort": 4443},
                                    {"containerPort": 53},
                                ],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "250m", "memory": "256Mi"},
                                    "limits": {"cpu": "1", "memory": "1Gi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "SLIVER_LHOST": "0.0.0.0",
            "SLIVER_MTLS_PORT": "31337",
            "SLIVER_HTTP_PORT": "4443",
            "SLIVER_DNS_PORT": "53",
            "PSK": "{{psk|generate_token}}",
        },
        "config_schema": {
            "SLIVER_LHOST": {"type": "string", "label": "Listen Host"},
            "SLIVER_MTLS_PORT": {"type": "string", "label": "mTLS Port"},
            "SLIVER_HTTP_PORT": {"type": "string", "label": "HTTP Port"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "1", "memory": "1Gi"},
        "ports": [
            {"name": "mtls", "containerPort": 31337, "servicePort": 31337},
            {"name": "https", "containerPort": 4443, "servicePort": 4443},
            {"name": "dns", "containerPort": 53, "servicePort": 53, "protocol": "UDP"},
        ],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "k8s-direct",
    },
    {
        "id": "pool-covenant-c2",
        "name": "Covenant C2",
        "service_type": "covenant",
        "description": "Covenant C2 — .NET C2 framework with web interface, Grunt implants, and advanced post-exploitation",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "covenant",
                                "image": "umbryx/covenant:latest",
                                "command": ["dotnet", "Covenant.dll"],
                                "args": [
                                    "--username",
                                    "admin",
                                    "--password",
                                    "{{admin_pass|default:CovenantAdmin123!}}",
                                ],
                                "ports": [
                                    {"containerPort": 7443},
                                    {"containerPort": 80},
                                    {"containerPort": 4444},
                                ],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "250m", "memory": "512Mi"},
                                    "limits": {"cpu": "1", "memory": "1Gi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "COVENANT_USER": "admin",
            "COVENANT_PASS": "{{admin_pass|generate_password}}",
            "COVENANT_HTTP_PORT": "80",
            "COVENANT_HTTPS_PORT": "7443",
            "COVENANT_LISTENER_PORT": "4444",
        },
        "config_schema": {
            "COVENANT_USER": {"type": "string", "label": "Admin Username"},
            "COVENANT_PASS": {"type": "string", "label": "Admin Password", "auto": True},
            "COVENANT_HTTPS_PORT": {"type": "string", "label": "HTTPS Port"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "1", "memory": "1Gi"},
        "ports": [
            {"name": "https", "containerPort": 7443, "servicePort": 7443},
            {"name": "http", "containerPort": 80, "servicePort": 80},
            {"name": "listener", "containerPort": 4444, "servicePort": 4444},
        ],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "k8s-direct",
    },
    {
        "id": "pool-nginx-redirector",
        "name": "Nginx Redirector",
        "service_type": "redirector",
        "description": "Nginx reverse-proxy redirector for domain fronting and traffic relay to upstream C2",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "image": "nginx:alpine",
                                "ports": [{"containerPort": 80}, {"containerPort": 443}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "64Mi"},
                                    "limits": {"cpu": "500m", "memory": "128Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "UPSTREAM_HOST": "{{upstream_host|default:127.0.0.1}}",
            "UPSTREAM_PORT": "{{upstream_port|default:8443}}",
            "LISTEN_PORT_HTTP": "80",
            "LISTEN_PORT_HTTPS": "443",
        },
        "config_schema": {
            "UPSTREAM_HOST": {"type": "string", "label": "Upstream Host"},
            "UPSTREAM_PORT": {"type": "string", "label": "Upstream Port"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "500m", "memory": "128Mi"},
        "ports": [
            {"name": "http", "containerPort": 80, "servicePort": 80},
            {"name": "https", "containerPort": 443, "servicePort": 443},
        ],
        "health_check_path": "/",
        "min_pool_size": 0,
        "image_delivery": "registry",
    },
    {
        "id": "pool-haproxy-relay",
        "name": "HAProxy Relay",
        "service_type": "relay",
        "description": "HAProxy TCP/HTTP relay for traffic forwarding and load balancing between redirectors and C2",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "haproxy",
                                "image": "haproxy:2.8-alpine",
                                "ports": [
                                    {"containerPort": 80},
                                    {"containerPort": 443},
                                    {"containerPort": 8443},
                                ],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "64Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "FRONTEND_PORT": "443",
            "BACKEND_HOST": "{{backend_host|default:127.0.0.1}}",
            "BACKEND_PORT": "{{backend_port|default:8443}}",
            "STATS_PORT": "8443",
        },
        "config_schema": {
            "FRONTEND_PORT": {"type": "string", "label": "Frontend Port"},
            "BACKEND_HOST": {"type": "string", "label": "Backend Host"},
            "BACKEND_PORT": {"type": "string", "label": "Backend Port"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "500m", "memory": "256Mi"},
        "ports": [
            {"name": "http", "containerPort": 80, "servicePort": 80},
            {"name": "https", "containerPort": 443, "servicePort": 443},
            {"name": "stats", "containerPort": 8443, "servicePort": 8443},
        ],
        "health_check_path": "/stats",
        "min_pool_size": 0,
        "image_delivery": "registry",
    },
    {
        "id": "pool-gophish",
        "name": "GoPhish",
        "service_type": "phishing",
        "description": "GoPhish phishing framework — campaign management, email templates, landing pages, and tracking",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "gophish",
                                "image": "gophish/gophish:latest",
                                "ports": [{"containerPort": 3333}, {"containerPort": 80}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "200m", "memory": "256Mi"},
                                    "limits": {"cpu": "1", "memory": "512Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "GOPHISH_ADMIN_USER": "admin",
            "GOPHISH_ADMIN_PASS": "{{admin_pass|generate_password}}",
            "ADMIN_PORT": "3333",
            "PHISH_PORT": "80",
        },
        "config_schema": {
            "GOPHISH_ADMIN_USER": {"type": "string", "label": "Admin User"},
            "GOPHISH_ADMIN_PASS": {"type": "string", "label": "Admin Password", "auto": True},
            "ADMIN_PORT": {"type": "string", "label": "Admin UI Port"},
            "PHISH_PORT": {"type": "string", "label": "Phishing Listener Port"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "1", "memory": "512Mi"},
        "ports": [
            {"name": "admin", "containerPort": 3333, "servicePort": 3333},
            {"name": "phishing", "containerPort": 80, "servicePort": 80},
        ],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "registry",
    },
    {
        "id": "pool-evilginx2",
        "name": "Evilginx2",
        "service_type": "phishing",
        "description": "Evilginx2 man-in-the-middle phishing framework — bypasses MFA via reverse proxy with session capture",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "evilginx2",
                                "image": "umbryx/evilginx2:latest",
                                "command": ["/app/evilginx"],
                                "args": ["-developer"],
                                "ports": [{"containerPort": 443}, {"containerPort": 53}],
                                "securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}},
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "200m", "memory": "128Mi"},
                                    "limits": {"cpu": "1", "memory": "512Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "LISTEN_HTTPS_PORT": "443",
            "LISTEN_DNS_PORT": "53",
            "EXTERNAL_IP": "{{external_ip|default:auto}}",
        },
        "config_schema": {
            "LISTEN_HTTPS_PORT": {"type": "string", "label": "HTTPS Port"},
            "LISTEN_DNS_PORT": {"type": "string", "label": "DNS Port"},
            "EXTERNAL_IP": {"type": "string", "label": "External IP"},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "1", "memory": "512Mi"},
        "ports": [
            {"name": "https", "containerPort": 443, "servicePort": 443},
            {"name": "dns", "containerPort": 53, "servicePort": 53, "protocol": "UDP"},
        ],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "k8s-direct",
    },
    {
        "id": "pool-chisel-tunnel",
        "name": "Chisel Tunnel",
        "service_type": "tunnel",
        "description": "Chisel HTTP/SOCKS tunnel server for pivoting and traffic tunneling over HTTP/WebSocket",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "chisel",
                                "image": "jpillora/chisel:latest",
                                "args": [
                                    "server",
                                    "--port",
                                    "8080",
                                    "--reverse",
                                    "--auth",
                                    "{{auth|default:user:pass}}",
                                ],
                                "ports": [{"containerPort": 8080}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "32Mi"},
                                    "limits": {"cpu": "250m", "memory": "64Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "LISTEN_PORT": "8080",
            "AUTH": "{{auth|generate_token}}",
        },
        "config_schema": {
            "LISTEN_PORT": {"type": "string", "label": "Listen Port"},
            "AUTH": {"type": "string", "label": "Auth Token", "auto": True},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "250m", "memory": "64Mi"},
        "ports": [{"name": "tunnel", "containerPort": 8080, "servicePort": 8080}],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "registry",
    },
    {
        "id": "pool-shadowsocks-proxy",
        "name": "Shadowsocks Proxy",
        "service_type": "proxy",
        "description": "Shadowsocks encrypted SOCKS5 proxy for secure traffic egress with multiple cipher support",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "shadowsocks",
                                "image": "shadowsocks/shadowsocks-libev:latest",
                                "command": ["/usr/bin/ss-server"],
                                "args": [
                                    "-s",
                                    "0.0.0.0",
                                    "-p",
                                    "8388",
                                    "-k",
                                    "{{password|default:changeme}}",
                                    "-m",
                                    "chacha20-ietf-poly1305",
                                    "-a",
                                    "nobody",
                                ],
                                "ports": [{"containerPort": 8388}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "32Mi"},
                                    "limits": {"cpu": "500m", "memory": "128Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "SERVER_PORT": "8388",
            "PASSWORD": "{{password|generate_password}}",
            "METHOD": "chacha20-ietf-poly1305",
        },
        "config_schema": {
            "SERVER_PORT": {"type": "string", "label": "Listen Port"},
            "PASSWORD": {"type": "string", "label": "Password", "auto": True},
            "METHOD": {
                "type": "select",
                "label": "Cipher",
                "options": ["chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"],
            },
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "500m", "memory": "128Mi"},
        "ports": [{"name": "socks", "containerPort": 8388, "servicePort": 8388}],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "registry",
    },
    {
        "id": "pool-iodine-dns-tunnel",
        "name": "Iodine DNS Tunnel",
        "service_type": "tunnel",
        "description": "Iodine DNS tunnel server — tunnels IPv4 traffic over DNS protocol for restricted network bypass",
        "manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "{{name}}"}},
                "template": {
                    "metadata": {"labels": {"app": "{{name}}"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "iodine",
                                "image": "umbryx/iodine:latest",
                                "command": ["iodined"],
                                "args": [
                                    "-f",
                                    "-P",
                                    "{{password|default:changeme}}",
                                    "10.0.0.1",
                                    "{{domain|default:t.example.com}}",
                                ],
                                "securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
                                "ports": [{"containerPort": 53, "protocol": "UDP"}],
                                "envFrom": [{"configMapRef": {"name": "{{name}}-config"}}],
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "32Mi"},
                                    "limits": {"cpu": "250m", "memory": "64Mi"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        "config_template": {
            "DOMAIN": "{{domain|default:t.example.com}}",
            "PASSWORD": "{{password|generate_password}}",
            "DNS_PORT": "53",
        },
        "config_schema": {
            "DOMAIN": {"type": "string", "label": "Tunnel Domain"},
            "PASSWORD": {"type": "string", "label": "Password", "auto": True},
        },
        "default_replicas": 1,
        "resource_limits": {"cpu": "250m", "memory": "64Mi"},
        "ports": [{"name": "dns", "containerPort": 53, "servicePort": 53, "protocol": "UDP"}],
        "health_check_path": None,
        "min_pool_size": 0,
        "image_delivery": "k8s-direct",
    },
]


_BUILTIN_SEED_VERSION = 2


def seed_builtin_instance_templates(db: Session) -> list[InstanceTemplate]:
    created = []
    for tpl_data in _BUILTIN_POOL_TEMPLATES:
        existing = (
            db.query(InstanceTemplate)
            .filter(
                InstanceTemplate.id == tpl_data["id"],
            )
            .first()
        )
        tpl = InstanceTemplate(
            id=tpl_data["id"],
            name=tpl_data["name"],
            service_type=tpl_data["service_type"],
            description=tpl_data.get("description"),
            manifest=tpl_data["manifest"],
            config_template=tpl_data["config_template"],
            config_schema=tpl_data["config_schema"],
            default_replicas=tpl_data.get("default_replicas", 1),
            resource_limits=tpl_data.get("resource_limits", {}),
            ports=tpl_data.get("ports", []),
            health_check_path=tpl_data.get("health_check_path"),
            min_pool_size=tpl_data.get("min_pool_size", 0),
            is_builtin=True,
            image_registry=tpl_data.get("image_registry"),
            image_delivery=tpl_data.get("image_delivery", "k8s-direct"),
            ssh_host=tpl_data.get("ssh_host"),
            created_by="system",
            ts=ts_now(),
        )
        if existing:
            if (existing.resource_limits or {}).get("_seed_version", 0) < _BUILTIN_SEED_VERSION:
                for col in (
                    "name",
                    "service_type",
                    "description",
                    "manifest",
                    "config_template",
                    "config_schema",
                    "default_replicas",
                    "resource_limits",
                    "ports",
                    "health_check_path",
                    "min_pool_size",
                    "image_registry",
                    "image_delivery",
                    "ssh_host",
                    "ts",
                ):
                    setattr(existing, col, getattr(tpl, col))
                limits = existing.resource_limits or {}
                limits["_seed_version"] = _BUILTIN_SEED_VERSION
                existing.resource_limits = limits
                created.append(existing)
        else:
            limits = tpl.resource_limits or {}
            limits["_seed_version"] = _BUILTIN_SEED_VERSION
            tpl.resource_limits = limits
            db.add(tpl)
            created.append(tpl)
    if created:
        db.commit()
    return created
