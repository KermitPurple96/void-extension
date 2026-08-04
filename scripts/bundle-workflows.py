#!/usr/bin/env python3
"""Convert Agent-zero-pentest workflow YAMLs into data/workflows.js.

Agent-zero organises workflows in three levels:

  atomic      one technique, with a decision tree the model walks step by step
  composite   an ordered chain of atomic workflows
  engagement  named phases, each pulling in workflows and extra checks

The panel needs one flat list, so each YAML becomes a workflow whose `steps`
carry the level's detail: an atomic workflow's decision tree becomes a single
step's `decisionTree`, while composite/engagement workflows expand their
references into one step apiece, keeping the referenced goal inline so the model
does not have to resolve paths at runtime.

Usage:
  python3 scripts/bundle-workflows.py <path-to-Agent-zero-pentest> [-o data/workflows.js]
"""
import argparse
import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

WF_SUBPATH = "patches/plugins/_pentest_kit/workflows"


def slug(path: pathlib.Path, root: pathlib.Path) -> str:
    """atomic/injection/sqli-form.yaml -> atomic/injection/sqli-form"""
    return str(path.relative_to(root).with_suffix("")).replace("\\", "/")


def load_all(root: pathlib.Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*.yaml")):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            print(f"  skip {p.name}: {e}", file=sys.stderr)
            continue
        if isinstance(data, dict) and data.get("name"):
            out[slug(p, root)] = data
    return out


def decision_tree(node: dict) -> list:
    return [
        {
            "action": d.get("action", ""),
            "approach": d.get("approach", ""),
            "ifPositive": d.get("if_positive", ""),
            "ifNegative": d.get("if_negative", ""),
            "stopWhen": d.get("stop_when", ""),
        }
        for d in (node.get("decision_tree") or [])
    ]


def atomic_step(ref: str, node: dict, step_id: str, depends: list) -> dict:
    """One atomic workflow becomes one step, detail preserved."""
    guidance = node.get("tool_guidance") or {}
    validation = node.get("validation") or {}
    return {
        "id": step_id,
        "name": node.get("name", step_id),
        "type": "SKILL",
        "skill": node.get("name", ""),
        "ref": ref,
        "dependsOn": depends,
        "category": node.get("category", ""),
        "goal": (node.get("goal") or "").strip(),
        "intrusive": bool((node.get("requires") or {}).get("intrusive")),
        "decisionTree": decision_tree(node),
        "toolGuidance": {
            "aiShould": (guidance.get("ai_should") or "").strip(),
            "useToolWhen": guidance.get("use_tool_when") or {},
        },
        "techniqueRefs": node.get("technique_refs") or [],
        "validation": {
            "mustReproduce": bool(validation.get("must_reproduce")),
            "contextCheck": validation.get("context_check", ""),
            "impactAssessment": validation.get("impact_assessment", ""),
        },
    }


def build(all_wf: dict) -> list:
    workflows = []
    for ref, node in all_wf.items():
        level = node.get("level", "atomic")
        wf = {
            "id": node["name"],
            "name": node["name"].replace("-", " ").title(),
            "description": (node.get("description") or "").strip(),
            "level": level,
            "category": node.get("category", level),
            "ref": ref,
            "steps": [],
        }

        if level == "atomic":
            wf["steps"] = [atomic_step(ref, node, node["name"], [])]

        elif level == "composite":
            prev = None
            for child_ref in node.get("chain") or []:
                child = all_wf.get(child_ref)
                if not child:
                    print(f"  {ref}: unresolved chain ref {child_ref}", file=sys.stderr)
                    continue
                step = atomic_step(child_ref, child, child["name"], [prev] if prev else [])
                wf["steps"].append(step)
                prev = step["id"]

        elif level == "engagement":
            prev = None
            for phase in node.get("phases") or []:
                pid = phase["name"].lower().replace(" ", "-").replace("&", "and")
                phase_step = {
                    "id": pid,
                    "name": phase["name"],
                    "type": "PHASE",
                    "skill": "",
                    "dependsOn": [prev] if prev else [],
                    "goal": (phase.get("goal") or "").strip(),
                    "intrusive": False,
                    "decisionTree": [],
                    "toolGuidance": {"aiShould": "", "useToolWhen": {}},
                    "techniqueRefs": [],
                    "extraChecks": phase.get("extra_checks") or [],
                    "validation": {
                        "mustReproduce": bool(phase.get("validation")),
                        "contextCheck": "",
                        "impactAssessment": "",
                    },
                    # Phases reference workflows; inline their goals so the model
                    # can follow the phase without resolving paths itself.
                    "includes": [
                        {
                            "ref": r,
                            "name": all_wf.get(r, {}).get("name", r),
                            "goal": (all_wf.get(r, {}).get("goal") or "").strip(),
                        }
                        for r in (phase.get("workflows") or [])
                    ],
                }
                wf["steps"].append(phase_step)
                prev = pid

        workflows.append(wf)

    order = {"engagement": 0, "composite": 1, "atomic": 2}
    workflows.sort(key=lambda w: (order.get(w["level"], 9), w["id"]))
    return workflows


HEADER = """/**
 * Void Extension — Workflow Definitions
 * Assigned to window.VOID_WORKFLOWS
 *
 * GENERATED by scripts/bundle-workflows.py from Agent-zero-pentest — do not edit
 * by hand. User edits belong in the panel (AI Settings -> Workflows), which
 * stores them as an overlay in chrome.storage rather than touching this file.
 *
 * Three levels, mirroring the source:
 *   atomic      one technique, whose decision tree the model walks step by step
 *   composite   an ordered chain of atomic workflows
 *   engagement  named phases pulling in workflows and extra checks
 *
 * Each step:
 *   id, name, type ('SKILL' | 'AGENT' | 'PHASE'), dependsOn[]
 *   goal            what the step is trying to establish
 *   intrusive       whether it sends attack traffic
 *   decisionTree[]  { action, approach, ifPositive, ifNegative, stopWhen }
 *   toolGuidance    { aiShould, useToolWhen }
 *   techniqueRefs[] technique slugs
 *   validation      { mustReproduce, contextCheck, impactAssessment }
 *   includes[]      (PHASE only) referenced workflows with their goals inlined
 *   extraChecks[]   (PHASE only) hybrid check ids to run in this phase
 */

window.VOID_WORKFLOWS = """


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="path to an Agent-zero-pentest checkout")
    ap.add_argument("-o", "--out", default="data/workflows.js")
    args = ap.parse_args()

    root = pathlib.Path(args.source) / WF_SUBPATH
    if not root.is_dir():
        sys.exit(f"no workflows directory at {root}")

    all_wf = load_all(root)
    workflows = build(all_wf)

    body = json.dumps(workflows, indent=2, ensure_ascii=False)
    pathlib.Path(args.out).write_text(HEADER + body + ";\n", encoding="utf-8")

    by_level = {}
    for w in workflows:
        by_level[w["level"]] = by_level.get(w["level"], 0) + 1
    steps = sum(len(w["steps"]) for w in workflows)
    trees = sum(len(s["decisionTree"]) for w in workflows for s in w["steps"])
    print(f"{args.out}: {len(workflows)} workflows ({by_level}), {steps} steps, {trees} decision nodes")


if __name__ == "__main__":
    main()
