"""
Chain Orchestrator v2 (skeleton)

This file contains a minimal skeleton that will later be expanded to
perform CVSS-aware chain selection and execution. For now it provides
an API to load templates and pick the highest-scored chain.
"""
from typing import Dict, List, Optional
from .chain_scorer import score_chain_template
import yaml
import os
import asyncio

# engine registry lookup
# avoid top-level import of backend.engines to prevent circular imports;
# import `get_engine` lazily inside runtime functions


class ChainOrchestratorV2:
    def __init__(self, templates_dir: str = None):
        self.templates_dir = templates_dir or os.path.join(os.path.dirname(__file__), "..", "chain_templates")
        self.templates: List[Dict] = []

    def load_templates(self):
        self.templates = []
        # load all yaml files in templates_dir
        if not os.path.isdir(self.templates_dir):
            return
        for fn in os.listdir(self.templates_dir):
            if not fn.endswith(".yaml") and not fn.endswith(".yml"):
                continue
            path = os.path.join(self.templates_dir, fn)
            with open(path, "r", encoding="utf-8") as fh:
                try:
                    tpl = yaml.safe_load(fh)
                    self.templates.append(tpl)
                except Exception:
                    continue

    def select_best_chain(self) -> Optional[Dict]:
        if not self.templates:
            self.load_templates()
        best = None
        best_score = -1.0
        for tpl in self.templates:
            score = score_chain_template(tpl)
            if score > best_score:
                best = tpl
                best_score = score
        return best

    def run_chain(self, chain: Dict, executor=None, context: Dict = None) -> Dict:
        """Execute a chain template using the provided executor.

        Args:
            chain: template dict with 'steps' list
            executor: callable(step: Dict, context: Dict) -> (bool, Any)
            context: optional context dict passed to executor

        Returns:
            dict with per-step results and overall success flag
        """
        if chain is None:
            return {"success": False, "reason": "no_chain"}

        if executor is None:
            # default executor: always succeed
            def executor(step, ctx):
                return True, {"msg": "ok"}

        ctx = context or {}
        results = []
        overall_success = True

        # lazy import to avoid circular imports
        from backend.engines.base import get_engine

        # import here to avoid circular import at module import time
        from backend.engines.base import get_engine

        # import lazily to avoid circular import
        from backend.engines.base import get_engine

        # import lazily to avoid circular import
        from backend.engines.base import get_engine

        # import get_engine lazily for async path
        from backend.engines.base import get_engine

        for step in chain.get("steps", []):
            try:
                ok, info = executor(step, ctx)
            except Exception as e:
                ok = False
                info = {"error": str(e)}

            results.append({"id": step.get("id"), "ok": bool(ok), "info": info})
            if not ok:
                overall_success = False

        return {
            "chain": chain.get("name") or chain.get("description"),
            "score": score_chain_template(chain),
            "steps": results,
            "success": overall_success,
        }

    async def run_chain_async(self, chain: Dict, target: str, vectors: List[Dict], timeout: Optional[int] = None, context: Dict = None) -> Dict:
        """Async executor for chain templates that maps steps to registered engines.

        Steps may include an `engine` field specifying a registered engine id.
        If present, the orchestrator will call `engine.scan(target, vectors_for_step)`
        and mark the step successful if the engine returns one or more findings.

        If a step does not specify an engine, it is treated as a logical step and
        considered successful by default unless an executor is provided.
        """
        if chain is None:
            return {"success": False, "reason": "no_chain"}

        ctx = context or {}
        results = []
        overall_success = True

        for step in chain.get("steps", []):
            engine_id = step.get("engine")
            required_findings = int(step.get("required_findings", 1))
            continue_on_failure = bool(step.get("continue_on_failure", False))
            if engine_id:
                # import dynamically to avoid any residual circular import issues
                import importlib
                engines_base = importlib.import_module("backend.engines.base")
                engine = engines_base.get_engine(engine_id)
                if not engine:
                    results.append({"id": step.get("id"), "ok": False, "info": {"error": "engine_not_found", "engine": engine_id}})
                    if not continue_on_failure:
                        overall_success = False
                    continue

                try:
                    # use the provided vectors for this step; adapters expect (target, vectors)
                    findings = await engine.scan(target, vectors)
                    fc = len(findings) if findings else 0
                    ok = fc >= required_findings
                    info = {"findings_count": fc}
                except Exception as e:
                    ok = False
                    info = {"error": str(e)}

                results.append({"id": step.get("id"), "ok": ok, "info": info, "engine": engine_id})
                if not ok and not continue_on_failure:
                    overall_success = False
            else:
                # logical step - succeed
                results.append({"id": step.get("id"), "ok": True, "info": {"note": "logical_step"}})

        return {
            "chain": chain.get("name") or chain.get("description"),
            "score": score_chain_template(chain),
            "steps": results,
            "success": overall_success,
        }
