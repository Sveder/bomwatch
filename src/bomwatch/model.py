"""The record that every collector returns."""

from dataclasses import asdict, dataclass

OK, FAILED, SKIPPED = "ok", "failed", "skipped"


@dataclass(frozen=True, order=True)
class Package:
    """One installed piece of software."""

    ecosystem: str
    name: str
    version: str
    location: str = ""
    source: str = ""

    def to_dict(self):
        """Return the package as a plain dict."""
        return asdict(self)

    @property
    def key(self):
        """Identity of the package, without the version."""
        return (self.ecosystem, self.name, self.location)
