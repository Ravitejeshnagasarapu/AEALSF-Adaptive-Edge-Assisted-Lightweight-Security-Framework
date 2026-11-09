from __future__ import annotations
from fastapi import FastAPI

from adaptive_engine.decision_engine import AdaptiveDecisionEngine
from adaptive_engine.execution_scheduler import AdaptiveExecutionScheduler
from api.routes import (
    authentication,
    blockchain,
    devices,
    edge,
    monitoring,
    tasks,
)
from blockchain.blockchain_client import BlockchainClient
from config.blockchain_config import BlockchainConfig
from config.edge_config import EdgeConfig
from config.security_config import SecurityConfig
from config.settings import get_settings
from cryptography.encryption_service import EncryptionService
from cryptography.homomorphic_encryption import ECElGamalHomomorphicEngine
from cryptography.key_manager import KeyManager
from cryptography.nizk_authentication import NIZKAuthenticator
from device.device_manager import DeviceManager
from edge.edge_server import EdgeClusterManager
from monitoring.metrics_collector import MetricsCollector
from monitoring.performance_monitor import PerformanceMonitor


class AEALSFRuntime:

    def __init__(
        self,
        security_config: SecurityConfig | None = None,
        blockchain_config: BlockchainConfig | None = None,
        edge_config: EdgeConfig | None = None,
    ) -> None:
        self.settings = get_settings()
        self.security_config = security_config or SecurityConfig()
        self.blockchain_config = blockchain_config or BlockchainConfig()
        self.edge_config = edge_config or EdgeConfig()

        self.nizk_auth = NIZKAuthenticator(self.security_config)
        self.he_engine = ECElGamalHomomorphicEngine(
            bsgs_max_bound=self.security_config.he_bsgs_max_bound
        )
        self.key_manager = KeyManager(self.nizk_auth, self.he_engine)
        self.encryption_service = EncryptionService(self.he_engine)

        self.blockchain_client = BlockchainClient(
            key_manager=self.key_manager,
            config=self.blockchain_config,
        )

        self.edge_cluster = EdgeClusterManager(
            key_manager=self.key_manager,
            blockchain_client=self.blockchain_client,
            he_engine=self.he_engine,
            nizk_auth=self.nizk_auth,
            config=self.edge_config,
        )

        self.decision_engine = AdaptiveDecisionEngine(
            failover_manager=self.edge_cluster.failover_manager,
            config=self.edge_config,
        )
        self.scheduler = AdaptiveExecutionScheduler(self.decision_engine)

        self.perf_monitor = PerformanceMonitor()
        self.metrics_collector = MetricsCollector(self.perf_monitor)

        self.device_manager = DeviceManager(
            key_manager=self.key_manager,
            nizk_auth=self.nizk_auth,
            he_engine=self.he_engine,
            encryption_service=self.encryption_service,
            blockchain_client=self.blockchain_client,
            edge_cluster=self.edge_cluster,
            decision_engine=self.decision_engine,
            perf_monitor=self.perf_monitor,
        )


def create_app(runtime: AEALSFRuntime | None = None) -> FastAPI:
    app = FastAPI(
        title="AEALSF — Adaptive Edge-Assisted Lightweight Security Framework",
        description=(
            "REST API for IoT Device Registration, Schnorr/DLP NIZK Authentication, "
            "EC-ElGamal Homomorphic Encryption, DVRC Consensus, and Resource-Aware Edge Scheduling."
        ),
        version="1.0.0",
    )
    app.state.runtime = runtime or AEALSFRuntime()

    app.include_router(devices.router)
    app.include_router(authentication.router)
    app.include_router(tasks.router)
    app.include_router(edge.router)
    app.include_router(blockchain.router)
    app.include_router(monitoring.router)

    @app.get("/health")
    def health_check():
        rt: AEALSFRuntime = app.state.runtime
        return {
            "status": "healthy",
            "framework": "AEALSF",
            "registered_devices": len(rt.device_manager.devices),
            "blockchain_height": len(rt.blockchain_client.chain) - 1,
            "online_edge_nodes": sum(
                1 for n in rt.edge_cluster.monitor.nodes.values() if n.online
            ),
        }

    return app


app = create_app()
