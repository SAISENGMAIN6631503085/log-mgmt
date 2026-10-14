"""Allowed values in the common event schema, used to validate search and dashboard filters.

Events are normalized and stored by the Go ingest service (/ingest); its normalize package
enforces the same lists when an event is built.
"""
from typing import Literal

Source = Literal["firewall", "network", "api", "crowdstrike", "aws", "m365", "ad"]
Action = Literal["allow", "deny", "create", "delete", "login", "logout", "alert", "quarantine"]
