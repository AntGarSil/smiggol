from waf_factory.models import EnforcementMode, Provider
from waf_factory.orchestrator import RuleFactoryOrchestrator


def test_generate_returns_blocked_result_without_llm() -> None:
    orchestrator = RuleFactoryOrchestrator()
    result = orchestrator.generate(
        cve_id="CVE-2024-12345",
        targets=[Provider.AWS, Provider.AZURE],
        mode=EnforcementMode.COUNT,
        use_llm=False,
    )

    assert result.artifacts == []
    assert result.rules == []
    assert result.replay_results == []
    assert result.promotion_state is not None
    assert result.promotion_state.value == "blocked"
