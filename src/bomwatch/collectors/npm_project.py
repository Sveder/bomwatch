"""Packages in the ``node_modules`` of every Node project under the roots.

Only the top level of each ``node_modules`` is read: the packages a project
(or its lock file) put there, not every nested copy.
"""

from bomwatch import walk
from bomwatch.collectors.npm import scan_node_modules


def collect(roots):
    """Return the top-level packages of each project found under ``roots``."""
    return [
        pkg
        for project in walk.find(roots).projects
        for pkg in scan_node_modules(project / "node_modules", "project", "npm-project")
    ]
