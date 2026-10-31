# Cisco ISE Authentication Log Analyzer

Parses supported Cisco ISE authentication log lines into event records and aggregates authentication failures by reason.

## Main entry points

- `src.ise.IseAuthEvent`
- `src.ise.IseLogAnalyzer` (`parse_line, aggregate_failures`)

## Run the tests

```bash
python -m unittest discover -s tests -v
```

The project uses the Python standard library; no third-party package is required.

## Scope

The input is exported or collected log text. The project does not connect to ISE, retrieve live reports, or parse every ISE event dictionary format.
