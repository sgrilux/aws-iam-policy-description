"""
Output formatting module for different output formats.

This module handles formatting and outputting policy analysis results in:
- Rich table format (for terminal display)
- JSON format
- CSV format
- HTML format
"""

import json
import csv
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table


def format_output_table(permission_map: List[Dict[str, Any]]) -> None:
    """Format output as a Rich table."""
    console = Console()
    statement_index = 1

    policy_table = Table(title="Policy Description", show_header=True)

    for statement in permission_map:
        sid = statement.get('Sid', '')
        policy_metadata = statement.get('PolicyMetadata', {})
        
        title = f"Statement {statement_index}"
        if sid:
            title += f" ({sid})"
        
        # Add policy information if available
        if policy_metadata:
            policy_name = policy_metadata.get('PolicyName', '')
            policy_type = policy_metadata.get('PolicyType', '')
            if policy_name:
                title += f" - {policy_name}"
            if policy_type:
                title += f" [{policy_type}]"

        statement_table = Table(title=title, show_header=True, expand=True)
        statement_table.add_column("Action", style="cyan")
        statement_table.add_column("Effect", style="green")
        statement_table.add_column("Resource", style="magenta")
        
        # Add Principal column for trust policies
        if statement.get('Principal'):
            statement_table.add_column("Principal", style="yellow")

        actions = statement.get('actions', {})
        action_table = Table(show_header=False, box=None)
        for action, description in actions.items():
            action_table.add_row(action, description)

        resource_table = Table(show_header=False, box=None)
        for resource in statement.get('Resource', []):
            resource_table.add_row(resource)
        
        # Handle Principal display
        if statement.get('Principal'):
            principal_table = Table(show_header=False, box=None)
            principals = statement.get('Principal', {})
            if isinstance(principals, dict):
                for principal_type, principal_values in principals.items():
                    if isinstance(principal_values, list):
                        for value in principal_values:
                            principal_table.add_row(f"{principal_type}: {value}")
                    else:
                        principal_table.add_row(f"{principal_type}: {principal_values}")
            else:
                principal_table.add_row(str(principals))
            
            statement_table.add_row(action_table, statement.get("Effect"), resource_table, principal_table)
        else:
            statement_table.add_row(action_table, statement.get("Effect"), resource_table)
        
        policy_table.add_row(statement_table)
        statement_index += 1
        policy_table.add_section()

    console.print(policy_table)


def format_output_json(permission_map: List[Dict[str, Any]]) -> str:
    """Format output as JSON."""
    return json.dumps(permission_map, indent=2)


def format_output_csv(permission_map: List[Dict[str, Any]]) -> str:
    """Format output as CSV."""
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Statement', 'PolicyName', 'PolicyType', 'Sid', 'Action', 'Description', 'Effect', 'Resource', 'Principal', 'Condition'])

    for i, statement in enumerate(permission_map, 1):
        actions = statement.get('actions', {})
        effect = statement.get('Effect', '')
        resources = statement.get('Resource', [])
        principals = statement.get('Principal', {})
        condition = json.dumps(statement.get('Condition', {})) if statement.get('Condition') else ''
        sid = statement.get('Sid', '')
        
        # Get policy metadata
        policy_metadata = statement.get('PolicyMetadata', {})
        policy_name = policy_metadata.get('PolicyName', '')
        policy_type = policy_metadata.get('PolicyType', '')
        
        # Format principal for CSV
        principal_str = ''
        if principals:
            if isinstance(principals, dict):
                principal_parts = []
                for p_type, p_values in principals.items():
                    if isinstance(p_values, list):
                        for value in p_values:
                            principal_parts.append(f"{p_type}: {value}")
                    else:
                        principal_parts.append(f"{p_type}: {p_values}")
                principal_str = '; '.join(principal_parts)
            else:
                principal_str = str(principals)

        for action, description in actions.items():
            for resource in resources:
                writer.writerow([i, policy_name, policy_type, sid, action, description, effect, resource, principal_str, condition])

    return output.getvalue()


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
        sid = statement.get('Sid', '')
        policy_metadata = statement.get('PolicyMetadata', {})
        
        title = f"Statement {i}"
        if sid:
            title += f" ({sid})"
        
        html += f'    <div class="statement">\n'
        html += f'        <div class="statement-title">{title}</div>\n'
        
        # Add policy information if available
        if policy_metadata:
            policy_name = policy_metadata.get('PolicyName', '')
            policy_type = policy_metadata.get('PolicyType', '')
            if policy_name or policy_type:
                html += f'        <div class="policy-info">Policy: {policy_name} ({policy_type})</div>\n'
        
        html += '        <table>\n'
        
        # Add Principal column header if principals exist
        if statement.get('Principal'):
            html += '            <tr><th>Action</th><th>Description</th><th>Effect</th><th>Resource</th><th>Principal</th></tr>\n'
        else:
            html += '            <tr><th>Action</th><th>Description</th><th>Effect</th><th>Resource</th></tr>\n'

        actions = statement.get('actions', {})
        effect = statement.get('Effect', '')
        resources = statement.get('Resource', [])
        principals = statement.get('Principal', {})
        effect_class = f"effect-{effect.lower()}"
        
        # Format principal for HTML
        principal_str = ''
        if principals:
            if isinstance(principals, dict):
                principal_parts = []
                for p_type, p_values in principals.items():
                    if isinstance(p_values, list):
                        for value in p_values:
                            principal_parts.append(f"{p_type}: {value}")
                    else:
                        principal_parts.append(f"{p_type}: {p_values}")
                principal_str = '<br>'.join(principal_parts)
            else:
                principal_str = str(principals)

        for action, description in actions.items():
            for resource in resources:
                html += f'            <tr>\n'
                html += f'                <td class="action">{action}</td>\n'
                html += f'                <td>{description}</td>\n'
                html += f'                <td class="{effect_class}">{effect}</td>\n'
                html += f'                <td class="action">{resource}</td>\n'
                if principals:
                    html += f'                <td class="principal">{principal_str}</td>\n'
                html += f'            </tr>\n'

        html += '        </table>\n'
        html += '    </div>\n'

    html += "</body>\n</html>"
    return html


def output_results(permission_map: List[Dict[str, Any]], output_format: str, output_file: Optional[str] = None) -> None:
    """Output results in the specified format.

    Args:
        permission_map: List of statement maps with action descriptions
        output_format: Output format (table, json, csv, html)
        output_file: Output file path (None for stdout)
    """
    if output_format == 'table':
        format_output_table(permission_map)
    elif output_format == 'json':
        content = format_output_json(permission_map)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)
        else:
            print(content)
    elif output_format == 'csv':
        content = format_output_csv(permission_map)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)
        else:
            print(content)
    elif output_format == 'html':
        content = format_output_html(permission_map)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)
        else:
            print(content)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")