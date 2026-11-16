# Security Policy

## Scope

This is an **academic lab project** (CodeAlpha cybersecurity internship). It is not deployed in
production and comes with no support guarantee. It is provided as is, under the MIT license.

| Version | Supported |
| --- | --- |
| `main` (latest commit) | best effort |

In scope:

- the custom Suricata rules in `suricata/custom.rules`;
- the automated response script `response/auto_block.py` (it runs `iptables` as root when
  `--no-dry-run` is set, so issues such as unintended blocking or command injection matter);
- the dashboard scripts in `dashboard/`.

Out of scope:

- Suricata, the Emerging Threats ruleset, `iptables` and other third-party tools: report issues
  to their maintainers;
- detection gaps that are already listed as known limitations in the [README](README.md#limitations).

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead: **Security** tab of this repository, then
**Report a vulnerability**. Include:

- the affected commit;
- steps to reproduce (use synthetic `eve.json` events, never real captured traffic);
- the expected impact.

This is a personal project: replies are best effort, with no guaranteed delay.

## Responsible use

The attack scenarios in `attack-simulation/` are meant **only** for an isolated lab network you
own. See the [ethical use section](README.md#ethical-use) of the README.
