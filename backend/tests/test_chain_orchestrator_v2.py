from backend.core.chain_orchestrator_v2 import ChainOrchestratorV2


def test_select_and_run_chain(tmp_path):
    orch = ChainOrchestratorV2()
    # point templates_dir to the repo's chain_templates (already present)
    orch.templates_dir = orch.templates_dir
    orch.load_templates()

    chain = orch.select_best_chain()
    assert chain is not None

    # executor that succeeds for first two steps and fails the last
    def executor(step, ctx):
        sid = step.get("id")
        if sid == "s3":
            return False, {"reason": "blocked"}
        return True, {"reason": "ok"}

    result = orch.run_chain(chain, executor=executor)
    assert result["chain"] is not None
    assert isinstance(result["score"], float)
    assert len(result["steps"]) >= 1
    # since executor fails on s3, overall success should be False
    assert result["success"] is False
