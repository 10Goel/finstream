import json
import subprocess
from dataclasses import replace

import pytest

from services.ai_sre_agent.remediation import (
    KubectlServerDryRunTransport,
    KubernetesMutationRequest,
    KubernetesTransportError,
)


def valid_body():
    return json.dumps(
        {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            (
                                "finstream.ai-sre/"
                                "authorization-id"
                            ): "auth-1",
                            (
                                "finstream.ai-sre/"
                                "permit-id"
                            ): "permit-1",
                            (
                                "finstream.ai-sre/"
                                "execution-claim-id"
                            ): "claim-1",
                            (
                                "finstream.ai-sre/"
                                "restart-requested-at"
                            ): (
                                "2026-10-23T20:00:00+00:00"
                            ),
                        }
                    }
                }
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def make_request():
    return KubernetesMutationRequest(
        namespace="finstream",
        deployment="processor",
        method="PATCH",
        api_path=(
            "/apis/apps/v1/namespaces/"
            "finstream/deployments/processor"
        ),
        content_type="application/merge-patch+json",
        body=valid_body(),
        request_digest="a" * 64,
    )


def test_transport_forces_server_dry_run(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(
            (command, kwargs)
        )

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(
                {
                    "metadata": {
                        "resourceVersion": "123"
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    transport = KubectlServerDryRunTransport()

    response = transport.patch_deployment(
        make_request()
    )

    assert response.accepted is True
    assert len(calls) == 1

    command, kwargs = calls[0]

    assert "--dry-run=server" in command
    assert "--field-manager=finstream-ai-sre" in command
    assert "processor" in command
    assert "finstream" in command

    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True


def test_transport_never_uses_shell(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout='{"metadata": {}}',
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    KubectlServerDryRunTransport().patch_deployment(
        make_request()
    )

    assert "shell" not in captured


def test_wrong_namespace_is_rejected():
    with pytest.raises(
        ValueError,
        match="namespace must be finstream",
    ):
        replace(
            make_request(),
            namespace="default",
        )


def test_wrong_deployment_is_rejected():
    with pytest.raises(
        ValueError,
        match="deployment must be processor",
    ):
        replace(
            make_request(),
            deployment="api",
        )


def test_wrong_api_path_is_rejected():
    request = replace(
        make_request(),
        api_path=(
            "/apis/apps/v1/namespaces/"
            "finstream/deployments/api"
        ),
    )

    with pytest.raises(
        KubernetesTransportError,
        match="API path",
    ):
        (
            KubectlServerDryRunTransport()
            .patch_deployment(request)
        )


def test_extra_patch_field_is_rejected():
    payload = json.loads(
        valid_body()
    )

    payload["spec"]["replicas"] = 0

    request = replace(
        make_request(),
        body=json.dumps(payload),
    )

    with pytest.raises(
        KubernetesTransportError,
        match="unexpected fields",
    ):
        (
            KubectlServerDryRunTransport()
            .patch_deployment(request)
        )


def test_extra_annotation_is_rejected():
    payload = json.loads(
        valid_body()
    )

    annotations = (
        payload["spec"]["template"]
        ["metadata"]["annotations"]
    )

    annotations[
        "malicious.example/command"
    ] = "anything"

    request = replace(
        make_request(),
        body=json.dumps(payload),
    )

    with pytest.raises(
        KubernetesTransportError,
        match="exactly allowlisted",
    ):
        (
            KubectlServerDryRunTransport()
            .patch_deployment(request)
        )


def test_kubectl_failure_returns_rejected_response(
    monkeypatch,
):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="server rejected patch",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    response = (
        KubectlServerDryRunTransport()
        .patch_deployment(
            make_request()
        )
    )

    assert response.accepted is False
    assert response.status_code == 1
    assert response.message == "server rejected patch"


def test_malformed_kubectl_json_is_rejected(
    monkeypatch,
):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="not-json",
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        KubernetesTransportError,
        match="malformed JSON",
    ):
        (
            KubectlServerDryRunTransport()
            .patch_deployment(
                make_request()
            )
        )


def test_transport_has_no_real_mutation_option():
    transport = KubectlServerDryRunTransport()

    assert not hasattr(
        transport,
        "dry_run",
    )

    assert not hasattr(
        transport,
        "execute_real",
    )

    assert not hasattr(
        transport,
        "apply",
    )
