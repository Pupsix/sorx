import json
import os

def format_txt(findings):
    blocks = []

    for target, target_findings in findings.items():
        lines = [target]

        if not target_findings:
            lines.append("  [No findings]")
        else:
            for finding_id, name in target_findings:
                lines.append(f"  [{finding_id}] {name}")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks) + "\n"


def format_json(findings):
    data = {}

    for target, target_findings in findings.items():
        data[target] = []

        for finding_id, name in target_findings:
            data[target].append({
                "id": finding_id,
                "name": name,
            })

    return json.dumps(data, indent=2)


def write(findings, path, json_output=False):
    if json_output:
        content = format_json(findings)
    else:
        content = format_txt(findings)

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        file.write(content)