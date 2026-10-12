"""One normalizer per source. Each takes (payload, tenant) and returns a validated Event."""
from collections.abc import Callable

from . import ad, api, aws, crowdstrike, firewall, m365, network
from .common import Event

NORMALIZERS: dict[str, Callable[..., Event]] = {
    "firewall": firewall.normalize,
    "network": network.normalize,
    "api": api.normalize,
    "crowdstrike": crowdstrike.normalize,
    "aws": aws.normalize,
    "m365": m365.normalize,
    "ad": ad.normalize,
}


def normalize(source: str, payload, tenant: str, **kwargs) -> Event:
    try:
        fn = NORMALIZERS[source]
    except KeyError:
        raise ValueError(f"unknown source {source!r}; expected one of {sorted(NORMALIZERS)}") from None
    return fn(payload, tenant, **kwargs)
