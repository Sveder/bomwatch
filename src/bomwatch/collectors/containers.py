"""Container images from docker and podman.

The name is the repository, the location the tag and the version the image
id, so pulling a new ``latest`` shows as a changed version.
"""

from bomwatch.model import Package
from bomwatch.runner import has, run

FORMAT = "{{.Repository}}\t{{.Tag}}\t{{.ID}}"


def parse(output, engine):
    """Turn ``<engine> image ls --format`` output into packages."""
    packages = []
    for line in output.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 3 or not parts[2]:
            continue
        repo, tag, image_id = parts
        if repo == "<none>":
            # Dangling images all share the name; the id keeps them apart.
            repo, tag = f"<none>@{image_id}", ""
        packages.append(Package(engine, repo, image_id, tag, engine))
    return packages


def collect_engine(engine):
    """Return the images of one engine; [] without it, None if it fails.

    A daemon that is not running is a failure, so its images are not
    reported as removed.
    """
    if not has(engine):
        return []
    output = run([engine, "image", "ls", "--no-trunc", "--format", FORMAT])
    return None if output is None else parse(output, engine)


def collect_docker(_roots):
    """Return docker images."""
    return collect_engine("docker")


def collect_podman(_roots):
    """Return podman images."""
    return collect_engine("podman")
