"""Infrastructure — concrete adapters for the ports in :mod:`cleanroom.ports`."""

from cleanroom.infrastructure.file_repository import FileSystemSnapshotRepository

__all__ = ["FileSystemSnapshotRepository"]
