"""Standard-library shared-session domain core."""

from .agent_adapter import (
    AgentAdapterConfigurationError,
    AgentRuntimeState,
    AgentRuntimeStatus,
    HermesAgentAdapter,
)
from .agent_planning import (
    AgentPlanningError,
    HermesReadOnlyPlanner,
    ReadOnlyPlan,
)
from .catalog_clustering import (
    CLUSTER_RULE_VERSION,
    TODAY_SCHEMA,
    TodayClusterView,
    TodayMaterialsProjection,
    build_today_materials,
)
from .catalog_models import (
    CATALOG_SYNC_SCHEMA,
    CatalogAssetView,
    CatalogItemInput,
    CatalogRootView,
    CatalogSnapshotBatch,
    CatalogSyncResult,
)
from .catalog_store import CatalogCursorConflict, CatalogStore, CatalogStoreError
from .content_understanding import (
    ContentPolicyView,
    ContentUnderstandingError,
    ContentUnderstandingService,
    ContentUnderstandingStore,
    SafeAnalysisAsset,
    StudyPack,
)
from .android_ocr_store import (
    ANDROID_OCR_SYNC_SCHEMA,
    AndroidOcrBatch,
    AndroidOcrReceipt,
    AndroidOcrStore,
    AndroidOcrStoreError,
)
from .content_projection import ContentProjection, ContentProjectionError
from .document_extraction import (
    DocumentExtractionError,
    DocumentExtractorSupervisor,
    ExtractedDocument,
)
from .autonomy_job import AutonomyJobError, AutonomyJobLease, AutonomyJobStore
from .errors import (
    ConversationAlreadyExistsError,
    ConversationNotFoundError,
    IdempotencyConflictError,
    PersistenceError,
    SharedSessionError,
    ValidationError,
)
from .models import (
    MESSAGE_ACCEPTED_EVENT,
    PROTOCOL_VERSION,
    AppendMessageResult,
    Conversation,
    ConversationEvent,
    ConversationMessage,
)
from .pairing_errors import PairingError
from .pairing_store import PairingStore
from .store import EventStore

__all__ = [
    "AgentAdapterConfigurationError",
    "AgentRuntimeState",
    "AgentRuntimeStatus",
    "AgentPlanningError",
    "ANDROID_OCR_SYNC_SCHEMA",
    "AndroidOcrBatch",
    "AndroidOcrReceipt",
    "AndroidOcrStore",
    "AndroidOcrStoreError",
    "CATALOG_SYNC_SCHEMA",
    "CLUSTER_RULE_VERSION",
    "CatalogAssetView",
    "CatalogCursorConflict",
    "CatalogItemInput",
    "CatalogRootView",
    "CatalogSnapshotBatch",
    "CatalogStore",
    "CatalogStoreError",
    "CatalogSyncResult",
    "ContentPolicyView",
    "ContentProjection",
    "ContentProjectionError",
    "ContentUnderstandingError",
    "ContentUnderstandingService",
    "ContentUnderstandingStore",
    "DocumentExtractionError",
    "DocumentExtractorSupervisor",
    "AutonomyJobError",
    "AutonomyJobLease",
    "AutonomyJobStore",
    "MESSAGE_ACCEPTED_EVENT",
    "PROTOCOL_VERSION",
    "AppendMessageResult",
    "Conversation",
    "ConversationAlreadyExistsError",
    "ConversationEvent",
    "ConversationMessage",
    "ConversationNotFoundError",
    "EventStore",
    "ExtractedDocument",
    "IdempotencyConflictError",
    "HermesAgentAdapter",
    "HermesReadOnlyPlanner",
    "PairingError",
    "PairingStore",
    "PersistenceError",
    "ReadOnlyPlan",
    "SafeAnalysisAsset",
    "SharedSessionError",
    "TODAY_SCHEMA",
    "StudyPack",
    "TodayClusterView",
    "TodayMaterialsProjection",
    "ValidationError",
    "build_today_materials",
]
