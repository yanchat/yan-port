"""Domain errors exposed by the YanPort CLI."""


class YanPortError(RuntimeError):
    """Base class for expected operator-facing failures."""


class ContextError(YanPortError):
    """The current checkout cannot be resolved or authenticated."""


class ConflictError(YanPortError):
    """A requested route, port, or reservation already has another owner."""


class CaddyError(YanPortError):
    """Caddy rejected a candidate configuration or could not be contacted."""
