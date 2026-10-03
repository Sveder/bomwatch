"""The record that every collector returns."""

from dataclasses import asdict, dataclass

OK, FAILED, SKIPPED = "ok", "failed", "skipped"


@dataclass(frozen=True, order=True)
class Package:
    """One installed piece of software, or one other watched record.

    ``flags`` is a comma separated list of risk names found when the record
    was collected (``pipe-to-shell``, ``hidden-unicode`` ...), see
    ``bomwatch.checks``.
    """

    ecosystem: str
    name: str
    version: str
    location: str = ""
    source: str = ""
    flags: str = ""

    def to_dict(self):
        """Return the package as a plain dict; ``flags`` only when set."""
        data = asdict(self)
        if not data["flags"]:
            del data["flags"]
        return data

    @property
    def key(self):
        """Identity of the package, without the version."""
        return (self.ecosystem, self.name, self.location)
