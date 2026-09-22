"""Threat detection engine subpackage.

Normalised Event -> Rule matching -> Alert generation

Rules are declarative configuration loaded from YAML bundles in ``rules/`` at
startup. The engine evaluates each ingested event against the enabled rules
and raises an alert when a rule's threshold is crossed within its time window.
"""