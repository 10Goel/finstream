import json
import subprocess

import pytest

from services.ai_sre_agent.remediation import (
    KubectlLiveTransport,
    KubernetesMutationMode,
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
                            ): "auth-live",
                            (
                                "finstream.ai-sre/"
                                "permit-id"
                            ): "permit-live",
                            (
                                "finstream.ai-sre/"
                                "execution-claim-id"
                            ): "claim-live",
                            (
                                "finstream.ai-sre/"
                                "restart-requested-at"
                            ): (
                                "2026-10-23T21:00:00+00:00"
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
        request_digest="b" * 64,
    )


def completed(command):
    return subprocess.CompletedProcess(
        args=command,
        returncode=0,
        stdout=json.dumps(
            {
                "metadata": {
                    "resourceVersion": "9001"
                }
            }
        ),
        stderr="",
    )


def test_live_transport_declares_live_mode():
    assert (
        KubectlLiveTransport.mode
        is KubernetesMutationMode.LIVE
    )


def test_live_transport_is_disabled_by_default(
    monkeypatch,
):
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        return completed(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    transport = KubectlLiveTransport()

    with pytest.raises(
        KubernetesTransportError,
        match="disabled",
    ):
        transport.patch_deployment(
            make_request()
        )

    assert called is False


def test_enabled_live_transport_calls_kubectl_once(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(
            (command, kwargs)
        )
        return completed(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    response = KubectlLiveTransport(
        live_enabled=True
    ).patch_deployment(
        make_request()
    )

    assert response.accepted is True
    assert response.status_code == 200
    assert response.resource_version == "9001"

    assert len(calls) == 1


def test_live_command_targets_only_finstream_processor(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return completed(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    KubectlLiveTransport(
        live_enabled=True
    ).patch_deployment(
        make_request()
    )

    command = calls[0]

    assert command[:4] == [
        "kubectl",
        "patch",
        "deployment",
        "processor",
    ]

    assert "--namespace" in command

    namespace_index = command.index(
        "--namespace"
    )

    assert (
        command[namespace_index + 1]
        == "finstream"
    )


def test_live_command_contains_no_dry_run(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return completed(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    KubectlLiveTransport(
        live_enabled=True
    ).patch_deployment(
        make_request()
    )

    assert all(
        not item.startswith("--dry-run")
        for item in calls[0]
    )


def test_live_transport_never_uses_shell(
    monkeypatch,
):
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        return completed(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    KubectlLiveTransport(
        live_enabled=True
    ).patch_deployment(
        make_request()
    )

    assert "shell" not in captured


def test_live_transport_uses_exact_merge_patch(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return completed(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = make_request()

    KubectlLiveTransport(
        live_enabled=True
    ).patch_deployment(
        request
    )

    command = calls[0]

    assert "--type=merge" in command
    assert "--patch" in command

    patch_index = command.index(
        "--patch"
    )

    assert (
        command[patch_index + 1]
        == request.body
    )


def test_live_transport_rejects_extra_patch_field():
    payload = json.loads(
        valid_body()
    )

    payload["spec"]["replicas"] = 0

    request = KubernetesMutationRequest(
        namespace="finstream",
        deployment="processor",
        method="PATCH",
        api_path=(
            "/apis/apps/v1/namespaces/"
            "finstream/deployments/processor"
        ),
        content_type="application/merge-patch+json",
        body=json.dumps(payload),
        request_digest="c" * 64,
    )

    with pytest.raises(
        KubernetesTransportError,
        match="unexpected fields",
    ):
        KubectlLiveTransport(
            live_enabled=True
        ).patch_deployment(
            request
        )


def test_live_kubectl_failure_is_fail_closed(
    monkeypatch,
):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="forbidden",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    response = KubectlLiveTransport(
        live_enabled=True
    ).patch_deployment(
        make_request()
    )

    assert response.accepted is False
    assert response.status_code == 1
    assert response.message == "forbidden"


def test_live_malformed_response_is_rejected(
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
        KubectlLiveTransport(
            live_enabled=True
        ).patch_deployment(
            make_request()
        )
