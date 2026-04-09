"""Plugin loader — discovers and loads third-party detectors via entry points."""

from __future__ import annotations

import logging

logger = logging.getLogger("aiguard.plugins")


def load_plugins() -> int:
    """Discover and load third-party detector plugins.

    Plugins register via the 'aiguard.detectors' entry point group:

        [project.entry-points."aiguard.detectors"]
        my_rule = "my_package.detectors:MyDetectorClass"

    Returns:
        Number of plugins loaded.
    """
    loaded = 0

    try:
        from importlib.metadata import entry_points
    except ImportError:
        return 0

    try:
        # Python 3.12+ / 3.10+ with importlib_metadata
        eps = entry_points(group="aiguard.detectors")
    except TypeError:
        # Python 3.9 fallback
        all_eps = entry_points()
        eps = all_eps.get("aiguard.detectors", [])

    for ep in eps:
        try:
            detector_cls = ep.load()
            # The class should self-register via @register decorator
            # when its module is imported, but we ensure it's in the registry
            from aiguard.detectors import _REGISTRY

            if hasattr(detector_cls, "rule_id"):
                if detector_cls.rule_id not in _REGISTRY:
                    _REGISTRY[detector_cls.rule_id] = detector_cls
                loaded += 1
                logger.debug(f"Loaded plugin detector: {detector_cls.rule_id}")
        except Exception as e:
            logger.warning(f"Failed to load plugin '{ep.name}': {e}")

    return loaded
