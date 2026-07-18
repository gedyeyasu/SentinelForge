from __future__ import annotations

from pathlib import Path


class CICDGenerator:
    """Generate CI/CD workflow templates for SentinelForge integration."""

    GITHUB_ACTIONS_TEMPLATE = """name: SentinelForge Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    # Run weekly on Sunday at 2 AM UTC
    - cron: '0 2 * * 0'
  workflow_dispatch:
    inputs:
      mode:
        description: 'Pentest mode'
        required: false
        default: 'standard'
        type: choice
        options:
          - quick
          - standard
          - full
          - pre_release

permissions:
  contents: read
  pull-requests: write
  security-events: write

env:
  SENTINELFORGE_MODE: ${{ github.event.inputs.mode || 'standard' }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install SentinelForge
        run: pip install sentinelforge

      - name: Run source code scan
        run: sentinelforge scan . --output scan-results.json --fail-on-finding
        continue-on-error: true

      - name: Run pattern and dependency scan
        run: |
          python -c "
          from sentinelforge.agents.exploit_patterns import ExploitPatternScanner
          from sentinelforge.agents.dependencies import DependencyParser
          from sentinelforge.agents.vuln_scanner import DependencyVulnerabilityScanner
          from pathlib import Path
          import json

          scanner = ExploitPatternScanner()
          result = scanner.scan_project(Path('.'))
          print(f'Pattern findings: {len(result.findings)}')

          parser = DependencyParser()
          try:
              manifest = parser.parse_project(Path('.'))
              vuln_scanner = DependencyVulnerabilityScanner()
              vuln_result = vuln_scanner.scan(manifest, repository_root='.')
              print(f'Dependency vulns: {len(vuln_result.vulnerabilities)}')
          except Exception as e:
              print(f'Dependency scan skipped: {e}')

          with open('pattern-results.json', 'w') as f:
              json.dump(result.to_dict(), f, indent=2)
          "

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sentinelforge-results
          path: |
            scan-results.json
            pattern-results.json

      - name: Fail on critical findings
        if: failure() || hashFiles('scan-results.json') != ''
        run: |
          python -c "
          import json, sys
          try:
              with open('scan-results.json') as f:
                  data = json.load(f)
              findings = data.get('findings', [])
              critical = [f for f in findings if f.get('severity') == 'critical']
              if critical:
                  print(f'CRITICAL: {len(critical)} critical findings detected')
                  sys.exit(1)
              print(f'Scan complete: {len(findings)} findings')
          except FileNotFoundError:
              print('No scan results found')
          "

  pentest:
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install SentinelForge
        run: pip install sentinelforge

      - name: Run pentest scan
        env:
          SENTINELFORGE_SCOPE: ${{ secrets.SENTINELFORGE_SCOPE }}
        run: |
          if [ -n "$SENTINELFORGE_SCOPE" ]; then
            echo "$SENTINELFORGE_SCOPE" > /tmp/scope.yaml
            sentinelforge pentest . --scope /tmp/scope.yaml --mode $SENTINELFORGE_MODE --source-only
          else
            sentinelforge pentest . --mode $SENTINELFORGE_MODE --source-only
          fi

      - name: Upload pentest results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sentinelforge-pentest
          path: .sentinelforge/control/runs.sqlite3
          retention-days: 30

  auto-patch:
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.event_name == 'pull_request'
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install SentinelForge
        run: pip install sentinelforge

      - name: Generate patches and create PR
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          sentinelforge scan . --output scan-results.json || true
          python -c "
          import json, subprocess, os
          from pathlib import Path

          try:
              with open('scan-results.json') as f:
                  data = json.load(f)
          except FileNotFoundError:
              print('No findings to patch')
              exit(0)

          findings = data.get('findings', [])
          if not findings:
              print('No findings detected')
              exit(0)

          print(f'Found {len(findings)} findings - manual review recommended')
          for f in findings[:5]:
              print(f'  [{f[\"severity\"]}] {f[\"title\"]}')
          "
"""

    @staticmethod
    def generate_github_actions(
        repo_dir: Path,
        *,
        schedule_cron: str = "0 2 * * 0",
        pentest_mode: str = "standard",
    ) -> Path:
        workflow_dir = repo_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)
        workflow_file = workflow_dir / "sentinelforge.yml"
        content = CICDGenerator.GITHUB_ACTIONS_TEMPLATE
        content = content.replace(
            "- cron: '0 2 * * 0'",
            f"- cron: '{schedule_cron}'",
        )
        content = content.replace(
            "default: 'standard'",
            f"default: '{pentest_mode}'",
        )
        workflow_file.write_text(content, encoding="utf-8")
        return workflow_file

    @staticmethod
    def generate_gitlab_ci(repo_dir: Path) -> Path:
        gitlab_ci = """sentinelforge-scan:
  stage: test
  image: python:3.12
  before_script:
    - pip install sentinelforge
  script:
    - sentinelforge scan . --output scan-results.json --fail-on-finding
    - |
      python -c "
      import json, sys
      try:
          with open('scan-results.json') as f:
              data = json.load(f)
          findings = data.get('findings', [])
          critical = [f for f in findings if f.get('severity') == 'critical']
          if critical:
              print(f'CRITICAL: {len(critical)} critical findings')
              sys.exit(1)
      except FileNotFoundError:
          pass
      "
  artifacts:
    paths:
      - scan-results.json
    when: always
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

sentinelforge-pentest:
  stage: test
  image: python:3.12
  before_script:
    - pip install sentinelforge
  script:
    - sentinelforge pentest . --mode standard --source-only
  artifacts:
    paths:
      - .sentinelforge/
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
"""
        workflow_file = repo_dir / ".gitlab-ci.yml"
        workflow_file.write_text(gitlab_ci, encoding="utf-8")
        return workflow_file

    @staticmethod
    def generate_pre_commit_config(repo_dir: Path) -> Path:
        config = """repos:
  - repo: local
    hooks:
      - id: sentinelforge-scan
        name: SentinelForge Security Scan
        entry: sentinelforge scan . --fail-on-finding
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-commit]
"""
        config_file = repo_dir / ".pre-commit-config.yaml"
        config_file.write_text(config, encoding="utf-8")
        return config_file
