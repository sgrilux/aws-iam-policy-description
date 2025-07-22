"""Output formatting module for different output formats.

This module handles formatting and outputting policy analysis results in:
- Rich table format (for terminal display)
- JSON format
- CSV format
- HTML format
"""

import csv
import json
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table


def format_output_table(permission_map: List[Dict[str, Any]]) -> None:
    """Format output as a Rich table."""
    console = Console()
    statement_index = 1

    policy_table = Table(title="Policy Description", show_header=True)

    for statement in permission_map:
        statement_table = _build_statement_table(statement, statement_index)
        policy_table.add_row(statement_table)
        statement_index += 1
        policy_table.add_section()

    console.print(policy_table)


def _build_statement_table(statement: Dict[str, Any], statement_index: int) -> Table:
    """Helper to build a Rich Table for a single statement."""
    sid = statement.get("Sid", "")
    policy_metadata = statement.get("PolicyMetadata", {})

    title = _build_statement_title(statement_index, sid, policy_metadata)

    statement_table = Table(title=title, show_header=True, expand=True)
    statement_table.add_column("Action", style="cyan")
    statement_table.add_column("Effect", style="green")
    statement_table.add_column("Resource", style="magenta")

    # Add Principal column for trust policies
    has_principal = statement.get("Principal") is not None
    if has_principal:
        statement_table.add_column("Principal", style="yellow")

    action_table = _build_action_table(statement.get("actions", {}))
    resource_table = _build_resource_table(statement.get("Resource", []))

    if has_principal:
        principal_table = _build_principal_table(statement.get("Principal"))
        statement_table.add_row(action_table, statement.get("Effect"), resource_table, principal_table)
    else:
        statement_table.add_row(action_table, statement.get("Effect"), resource_table)

    return statement_table


def _build_statement_title(statement_index: int, sid: str, policy_metadata: Dict[str, Any]) -> str:
    title = f"Statement {statement_index}"
    if sid:
        title += f" ({sid})"
    if policy_metadata:
        policy_name = policy_metadata.get("PolicyName", "")
        policy_type = policy_metadata.get("PolicyType", "")
        if policy_name:
            title += f" - {policy_name}"
        if policy_type:
            title += f" [{policy_type}]"
    return title


def _build_action_table(actions: Dict[str, Any]) -> Table:
    action_table = Table(show_header=False, box=None)
    for action, description in actions.items():
        action_table.add_row(action, description)
    return action_table


def _build_resource_table(resources: List[Any]) -> Table:
    resource_table = Table(show_header=False, box=None)
    for resource in resources:
        resource_table.add_row(resource)
    return resource_table


def _build_principal_table(principals: Any) -> Table:
    principal_table = Table(show_header=False, box=None)
    if isinstance(principals, dict):
        for principal_type, principal_values in principals.items():
            if isinstance(principal_values, list):
                for value in principal_values:
                    principal_table.add_row(f"{principal_type}: {value}")
            else:
                principal_table.add_row(f"{principal_type}: {principal_values}")
    else:
        principal_table.add_row(str(principals))
    return principal_table


def format_output_json(permission_map: List[Dict[str, Any]]) -> str:
    """Format output as JSON."""
    return json.dumps(permission_map, indent=2)


def format_output_csv(permission_map: List[Dict[str, Any]]) -> str:
    """Format output as CSV."""
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Statement",
            "PolicyName",
            "PolicyType",
            "Sid",
            "Action",
            "Description",
            "Effect",
            "Resource",
            "Principal",
            "Condition",
        ]
    )

    for i, statement in enumerate(permission_map, 1):
        actions = statement.get("actions", {})
        effect = statement.get("Effect", "")
        resources = statement.get("Resource", [])
        principals = statement.get("Principal", {})
        condition = json.dumps(statement.get("Condition", {})) if statement.get("Condition") else ""
        sid = statement.get("Sid", "")

        # Get policy metadata
        policy_metadata = statement.get("PolicyMetadata", {})
        policy_name = policy_metadata.get("PolicyName", "")
        policy_type = policy_metadata.get("PolicyType", "")

        # Format principal for CSV
        principal_str = ""
        if principals:
            if isinstance(principals, dict):
                principal_parts = []
                for p_type, p_values in principals.items():
                    if isinstance(p_values, list):
                        for value in p_values:
                            principal_parts.append(f"{p_type}: {value}")
                    else:
                        principal_parts.append(f"{p_type}: {p_values}")
                principal_str = "; ".join(principal_parts)
            else:
                principal_str = str(principals)

        for action, description in actions.items():
            for resource in resources:
                writer.writerow(
                    [i, policy_name, policy_type, sid, action, description, effect, resource, principal_str, condition]
                )

    return output.getvalue()


def _format_principal_html(principals: Any) -> str:
    """Helper to format principal for HTML output."""
    if not principals:
        return ""
    if isinstance(principals, dict):
        principal_parts = []
        for p_type, p_values in principals.items():
            if isinstance(p_values, list):
                for value in p_values:
                    principal_parts.append(f"{p_type}: {value}")
            else:
                principal_parts.append(f"{p_type}: {p_values}")
        return "<br>".join(principal_parts)
    return str(principals)


def _generate_html_table_rows(actions, effect, resources, principals, effect_class, has_principal):
    """Helper to generate HTML table rows for a statement."""
    rows = ""
    principal_str = _format_principal_html(principals)
    for action, description in actions.items():
        for resource in resources:
            rows += "            <tr>\n"
            rows += f'                <td class="action">{action}</td>\n'
            rows += f"                <td>{description}</td>\n"
            rows += f'                <td class="{effect_class}">{effect}</td>\n'
            rows += f'                <td class="action">{resource}</td>\n'
            if has_principal:
                rows += f'                <td class="principal">{principal_str}</td>\n'
            rows += "            </tr>\n"
    return rows


def format_output_html(permission_map: List[Dict[str, Any]]) -> str:
    """Format output as HTML."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>IAM Policy Description</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .statement { margin-bottom: 30px; }
        .statement-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
        .policy-info { font-size: 14px; color: #666; margin-bottom: 5px; }
        .action { font-family: monospace; }
        .effect-allow { color: green; }
        .effect-deny { color: red; }
        .principal { font-style: italic; }
    </style>
</head>
<body>
    <h1>IAM Policy Description</h1>
"""

    for i, statement in enumerate(permission_map, 1):
        sid = statement.get("Sid", "")
        policy_metadata = statement.get("PolicyMetadata", {})

        title = f"Statement {i}"
        if sid:
            title += f" ({sid})"

        html += '    <div class="statement">\n'
        html += f'        <div class="statement-title">{title}</div>\n'

        # Add policy information if available
        if policy_metadata:
            policy_name = policy_metadata.get("PolicyName", "")
            policy_type = policy_metadata.get("PolicyType", "")
            if policy_name or policy_type:
                html += f'        <div class="policy-info">Policy: {policy_name} ({policy_type})</div>\n'

        html += "        <table>\n"

        actions = statement.get("actions", {})
        effect = statement.get("Effect", "")
        resources = statement.get("Resource", [])
        principals = statement.get("Principal", {})
        effect_class = f"effect-{effect.lower()}"
        has_principal = bool(principals)

        # Add Principal column header if principals exist
        if has_principal:
            html += "            <tr><th>Action</th><th>Description</th><th>Effect</th><th>Resource</th><th>Principal</th></tr>\n"
        else:
            html += "            <tr><th>Action</th><th>Description</th><th>Effect</th><th>Resource</th></tr>\n"

        html += _generate_html_table_rows(actions, effect, resources, principals, effect_class, has_principal)

        html += "        </table>\n"
        html += "    </div>\n"

    html += "</body>\n</html>"
    return html


def output_results(
    results,  # Union[Dict[str, Any], List[Dict[str, Any]]]
    output_format: str,
    output_file: Optional[str] = None,
    analysis_mode: str = "actions",
) -> None:
    """Output results in the specified format.

    Args:
        results: Dictionary containing 'actions'/'bedrock_description' keys OR list of permission maps (legacy)
        output_format: Output format (table, json, csv, html)
        output_file: Output file path (None for stdout)
        analysis_mode: Analysis mode (actions, description, full)
    """
    # Handle legacy format (direct permission map list)
    if isinstance(results, list):
        permission_map = results
        _output_actions_only(permission_map, output_format, output_file)
        return

    # Handle new format (dictionary with analysis results)
    if not isinstance(results, dict):
        raise ValueError(f"Results must be a dictionary or list, got {type(results)}")

    if analysis_mode == "description" and "bedrock_description" in results:
        # Output only Bedrock description
        content = results["bedrock_description"]
        context = results.get("context", {})

        if output_format == "table" and context:
            # Show context info in table format
            from rich.console import Console
            from rich.panel import Panel

            console = Console()
            context_type = context.get("type", "")
            context_name = context.get("name", "")
            policy_count = context.get("policy_count", 0)
            policies = context.get("policies", [])

            context_title = f"Analysis for IAM {context_type.title()}: {context_name}"
            context_content = f"Attached policies ({policy_count}): {', '.join(policies)}"
            console.print(Panel(context_content, title=context_title, style="blue"))
            console.print()
            if content:
                console.print(Panel(content, title="AI Policy Analysis (via Amazon Bedrock)", expand=False))
            else:
                console.print(
                    Panel("Bedrock analysis unavailable", title="AI Policy Analysis (via Amazon Bedrock)", style="red")
                )
        else:
            # Plain text output (or file output)
            if context:
                context_header = f"# Analysis for IAM {context.get('type', '').title()}: {context.get('name', '')}\n"
                context_header += f"# Attached policies ({context.get('policy_count', 0)}): {', '.join(context.get('policies', []))}\n\n"
                content = context_header + content

            if output_file:
                with open(output_file, "w") as f:
                    f.write(content)
            else:
                print(content)

    elif analysis_mode == "actions" and "actions" in results:
        # Output only actions (existing functionality)
        permission_map = results["actions"]
        context = results.get("context", {})

        if output_format == "table" and context:
            # Show context info before actions in table format
            from rich.console import Console
            from rich.panel import Panel

            console = Console()
            context_type = context.get("type", "")
            context_name = context.get("name", "")
            policy_count = context.get("policy_count", 0)
            policies = context.get("policies", [])

            context_title = f"Analysis for IAM {context_type.title()}: {context_name}"
            context_content = f"Attached policies ({policy_count}): {', '.join(policies)}"
            console.print(Panel(context_content, title=context_title, style="blue"))
            console.print()

        _output_actions_only(permission_map, output_format, output_file)

    elif analysis_mode == "full":
        # Output both Bedrock description and actions
        _output_combined_results(results, output_format, output_file)
    else:
        raise ValueError(f"Invalid analysis mode or missing data: {analysis_mode}")


def _output_combined_table(context: Dict[str, Any], bedrock_description: str, actions: List[Dict[str, Any]]) -> None:
    """Output combined results in table format."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    if context:
        context_type = context.get("type", "")
        context_name = context.get("name", "")
        policy_count = context.get("policy_count", 0)
        policies = context.get("policies", [])
        context_title = f"Analysis for IAM {context_type.title()}: {context_name}"
        context_content = f"Attached policies ({policy_count}): {', '.join(policies)}"
        console.print(Panel(context_content, title=context_title, style="blue"))
        console.print()
    if bedrock_description:
        console.print(Panel(bedrock_description, title="AI Policy Analysis (via Amazon Bedrock)", expand=False))
    else:
        console.print(
            Panel("Bedrock analysis unavailable", title="AI Policy Analysis (via Amazon Bedrock)", style="red")
        )
    if actions:
        format_output_table(actions)


def _output_combined_json(
    context: Dict[str, Any], bedrock_description: str, actions: List[Dict[str, Any]], output_file: Optional[str]
) -> None:
    """Output combined results in JSON format."""
    combined = {
        "bedrock_description": bedrock_description,
        "actions": actions,
        "context": context,
    }
    content = json.dumps(combined, indent=2)
    if output_file:
        with open(output_file, "w") as f:
            f.write(content)
    else:
        print(content)


def _output_combined_csv(bedrock_description: str, actions: List[Dict[str, Any]], output_file: Optional[str]) -> None:
    """Output combined results in CSV format."""
    content = format_output_csv(actions)
    if output_file:
        with open(output_file, "w") as f:
            if bedrock_description:
                f.write(f"# Bedrock description:\n# {bedrock_description.replace(chr(10), chr(10)+'# ')}\n")
            f.write(content)
    else:
        if bedrock_description:
            print(f"# Bedrock description:\n# {bedrock_description.replace(chr(10), chr(10)+'# ')}\n")
        print(content)


def _output_combined_html(bedrock_description: str, actions: List[Dict[str, Any]], output_file: Optional[str]) -> None:
    """Output combined results in HTML format."""
    html_content = ""
    if bedrock_description:
        html_content += f"<div style='margin-bottom:20px;'><strong>AI Policy Analysis (via Amazon Bedrock):</strong><br>{bedrock_description}</div>\n"
    html_content += format_output_html(actions)
    if output_file:
        with open(output_file, "w") as f:
            f.write(html_content)
    else:
        print(html_content)


def _output_combined_results(results: dict, output_format: str, output_file: Optional[str] = None) -> None:
    """Output both Bedrock description and actions."""
    bedrock_description = results.get("bedrock_description", "")
    context = results.get("context", {})
    actions = results.get("actions", [])

    if output_format == "table":
        _output_combined_table(context, bedrock_description, actions)
    elif output_format == "json":
        _output_combined_json(context, bedrock_description, actions, output_file)
    elif output_format == "csv":
        _output_combined_csv(bedrock_description, actions, output_file)
    elif output_format == "html":
        _output_combined_html(bedrock_description, actions, output_file)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def _output_actions_only(
    permission_map: List[Dict[str, Any]], output_format: str, output_file: Optional[str] = None
) -> None:
    """Output only actions analysis (original functionality)."""
    if output_format == "table":
        format_output_table(permission_map)
    elif output_format == "json":
        content = format_output_json(permission_map)
        if output_file:
            with open(output_file, "w") as f:
                f.write(content)
        else:
            print(content)
    elif output_format == "csv":
        content = format_output_csv(permission_map)
        if output_file:
            with open(output_file, "w") as f:
                f.write(content)
        else:
            print(content)
    elif output_format == "html":
        content = format_output_html(permission_map)
        if output_file:
            with open(output_file, "w") as f:
                f.write(content)
        else:
            print(content)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
