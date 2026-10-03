from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes.client import ApiException

from services.ai_sre_agent.models import (
    EvidenceSource,
    EvidenceTrustLevel,
)
from services.ai_sre_agent.tools.kubernetes import (
    KubernetesDiagnosticError,
    KubernetesDiagnosticTool,
)


def pod(
    name,
    *,
    phase="Running",
    ready=True,
    restarts=0,
):
    conditions = [
        SimpleNamespace(
            type="Ready",
            status="True" if ready else "False",
        )
    ]

    container_statuses = [
        SimpleNamespace(
            restart_count=restarts,
        )
    ]

    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=name,
        ),
        status=SimpleNamespace(
            phase=phase,
            conditions=conditions,
            container_statuses=container_statuses,
        ),
    )


def deployment(
    *,
    desired=1,
    ready=1,
    available=1,
    updated=1,
):
    return SimpleNamespace(
        spec=SimpleNamespace(
            replicas=desired,
        ),
        status=SimpleNamespace(
            ready_replicas=ready,
            available_replicas=available,
            updated_replicas=updated,
        ),
    )


def event(
    object_name,
    *,
    reason="Started",
    event_type="Normal",
    message="Container started",
    timestamp=None,
):
    timestamp = timestamp or datetime(
        2026,
        10,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    return SimpleNamespace(
        type=event_type,
        reason=reason,
        message=message,
        event_time=None,
        last_timestamp=timestamp,
        first_timestamp=None,
        metadata=SimpleNamespace(
            creation_timestamp=timestamp,
        ),
        involved_object=SimpleNamespace(
            name=object_name,
        ),
    )


def make_tool(
    *,
    pods=None,
    deployment_value=None,
    events=None,
):
    core = MagicMock()
    apps = MagicMock()

    core.list_namespaced_pod.return_value = (
        SimpleNamespace(
            items=pods or [],
        )
    )

    core.list_namespaced_event.return_value = (
        SimpleNamespace(
            items=events or [],
        )
    )

    apps.read_namespaced_deployment.return_value = (
        deployment_value or deployment()
    )

    return (
        KubernetesDiagnosticTool(
            core,
            apps,
            namespace="finstream",
        ),
        core,
        apps,
    )


def test_deployment_status_reports_healthy():
    tool, _, apps = make_tool()

    evidence = tool.get_deployment_status(
        incident_id="inc-test",
        service="producer",
    )

    assert evidence.source is EvidenceSource.KUBERNETES
    assert (
        evidence.trust_level
        is EvidenceTrustLevel.DIRECT_OBSERVATION
    )
    assert evidence.service == "producer"
    assert evidence.metadata["healthy"] is True
    assert evidence.metadata["desired_replicas"] == 1
    assert evidence.metadata["ready_replicas"] == 1

    apps.read_namespaced_deployment.assert_called_once_with(
        name="producer",
        namespace="finstream",
    )


def test_deployment_status_reports_unavailable():
    tool, _, _ = make_tool(
        deployment_value=deployment(
            desired=1,
            ready=0,
            available=0,
            updated=1,
        )
    )

    evidence = tool.get_deployment_status(
        incident_id="inc-test",
        service="producer",
    )

    assert evidence.metadata["healthy"] is False
    assert "not fully available" in evidence.summary


def test_scaled_to_zero_is_not_healthy():
    tool, _, _ = make_tool(
        deployment_value=deployment(
            desired=0,
            ready=0,
            available=0,
            updated=0,
        )
    )

    evidence = tool.get_deployment_status(
        incident_id="inc-test",
        service="producer",
    )

    assert evidence.metadata["healthy"] is False
    assert evidence.metadata["desired_replicas"] == 0


def test_get_pods_returns_bounded_state():
    tool, core, _ = make_tool(
        pods=[
            pod("producer-abc", restarts=2),
            pod(
                "producer-def",
                phase="Pending",
                ready=False,
            ),
        ]
    )

    evidence = tool.get_pods(
        incident_id="inc-test",
        service="producer",
    )

    assert evidence.metadata["pod_count"] == 2
    assert evidence.metadata["running_count"] == 1
    assert evidence.metadata["ready_count"] == 1
    assert evidence.metadata["pods"][0]["restart_count"] == 2

    core.list_namespaced_pod.assert_called_once_with(
        namespace="finstream",
        label_selector="app=producer",
    )


def test_restart_count_sums_container_restarts():
    tool, _, _ = make_tool(
        pods=[
            pod("producer-a", restarts=2),
            pod("producer-b", restarts=3),
        ]
    )

    evidence = tool.get_restart_count(
        incident_id="inc-test",
        service="producer",
    )

    assert evidence.metadata["total_restarts"] == 5
    assert evidence.metadata["per_pod"] == {
        "producer-a": 2,
        "producer-b": 3,
    }


def test_recent_events_filters_service_and_limits_results():
    tool, _, _ = make_tool(
        events=[
            event(
                "producer-aaa",
                reason="BackOff",
                event_type="Warning",
            ),
            event("api-bbb"),
            event("producer"),
        ]
    )

    evidence = tool.get_recent_events(
        incident_id="inc-test",
        service="producer",
        max_events=1,
    )

    assert evidence.metadata["event_count"] == 1
    assert len(evidence.metadata["events"]) == 1
    assert evidence.metadata["events"][0]["object"] in {
        "producer",
        "producer-aaa",
    }


def test_recent_events_rejects_unbounded_limit():
    tool, _, _ = make_tool()

    with pytest.raises(
        ValueError,
        match="max_events must be between 1 and 50",
    ):
        tool.get_recent_events(
            incident_id="inc-test",
            service="producer",
            max_events=500,
        )


def test_unknown_service_is_rejected_before_api_call():
    tool, core, apps = make_tool()

    with pytest.raises(
        ValueError,
        match="Unsupported FinStream service",
    ):
        tool.get_deployment_status(
            incident_id="inc-test",
            service="random-workload",
        )

    apps.read_namespaced_deployment.assert_not_called()
    core.list_namespaced_pod.assert_not_called()


def test_empty_namespace_is_rejected():
    with pytest.raises(
        ValueError,
        match="namespace must not be empty",
    ):
        KubernetesDiagnosticTool(
            MagicMock(),
            MagicMock(),
            namespace=" ",
        )


def test_api_exception_is_wrapped():
    core = MagicMock()
    apps = MagicMock()

    apps.read_namespaced_deployment.side_effect = (
        ApiException(status=403)
    )

    tool = KubernetesDiagnosticTool(
        core,
        apps,
    )

    with pytest.raises(
        KubernetesDiagnosticError,
        match="Unable to read Kubernetes deployment",
    ):
        tool.get_deployment_status(
            incident_id="inc-test",
            service="producer",
        )
