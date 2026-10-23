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


def success(command):
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
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return success(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        KubernetesTransportError,
        match="disabled",
    ):
        KubectlLiveTransport().patch_deployment(
            make_request()
        )

    assert calls == []


def test_enabled_live_transport_runs_preflight_then_live(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return success(command)

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
    assert len(calls) == 2

    assert "--dry-run=server" in calls[0]
    assert "--dry-run=server" not in calls[1]


def test_both_commands_target_only_processor(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return success(command)

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

    for command in calls:
        assert command[:4] == [
            "kubectl",
            "patch",
            "deployment",
            "processor",
        ]

        index = command.index(
            "--namespace"
        )

        assert command[index + 1] == "finstream"


def test_preflight_and_live_use_identical_patch(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return success(command)

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

    for command in calls:
        index = command.index(
            "--patch"
        )

        assert command[index + 1] == request.body


def test_preflight_failure_blocks_live_mutation(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="preflight forbidden",
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
    assert len(calls) == 1
    assert "--dry-run=server" in calls[0]


def test_malformed_preflight_blocks_live_mutation(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)

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
        match="live preflight",
    ):
        KubectlLiveTransport(
            live_enabled=True
        ).patch_deployment(
            make_request()
        )

    assert len(calls) == 1


def test_live_command_contains_no_dry_run(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return success(command)

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
        for item in calls[1]
    )


def test_transport_never_uses_shell(
    monkeypatch,
):
    kwargs_seen = []

    def fake_run(command, **kwargs):
        kwargs_seen.append(kwargs)
        return success(command)

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

    assert len(kwargs_seen) == 2

    for kwargs in kwargs_seen:
        assert "shell" not in kwargs


def test_extra_patch_field_is_rejected_before_kubectl(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return success(command)

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

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

    assert calls == []


def test_live_failure_is_fail_closed(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)

        if len(calls) == 1:
            return success(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="live forbidden",
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
    assert response.message == "live forbidden"
    assert len(calls) == 2


def test_malformed_live_response_is_rejected(
    monkeypatch,
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)

        if len(calls) == 1:
            return success(command)

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
        match="live mutation",
    ):
        KubectlLiveTransport(
            live_enabled=True
        ).patch_deployment(
            make_request()
        )


def test_live_response_resource_version_is_returned(
    monkeypatch,
):
    def fake_run(command, **kwargs):
        return success(command)

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

    assert response.resource_version == "9001"
