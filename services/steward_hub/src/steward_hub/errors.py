"""Safe domain errors for the shared-session event store."""


class SharedSessionError(Exception):
    """Base class for errors safe to expose to a local caller."""


class ValidationError(SharedSessionError):
    """Raised when a caller supplies an invalid field."""


class ConversationNotFoundError(SharedSessionError):
    """Raised when a conversation does not exist."""


class ConversationAlreadyExistsError(SharedSessionError):
    """Raised when a conversation identifier is already present."""


class IdempotencyConflictError(SharedSessionError):
    """Raised when an idempotency key is reused with different input."""


class PersistenceError(SharedSessionError):
    """Raised when a transaction cannot be completed safely."""
