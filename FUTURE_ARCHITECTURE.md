# TLSXtractor Future Architecture Plan
**Version:** 2.0 Architecture Design
**Date:** November 10, 2025
**Status:** Planning Phase
**Target Release:** Q2 2026

---

## Executive Summary

This document outlines the architectural vision for TLSXtractor 2.0, transforming it from a standalone CLI tool into a scalable, enterprise-grade reconnaissance platform with six major enhancements:

1. **Plugin System** - Extensible domain extraction
2. **Configuration Management** - YAML/TOML support with hot-reloading
3. **Event Bus** - Real-time monitoring and webhooks
4. **Distributed Scanning** - Horizontal scaling across workers
5. **Web API** - REST/GraphQL/WebSocket interfaces
6. **Advanced Analytics** - Certificate chains and domain graphs

### Expected Impact

- **10x Scalability** via distributed workers
- **50% Faster Development** through plugins
- **100% Observability** with event bus
- **5x Easier Integration** via Web API
- **Deep Intelligence** from advanced analytics

---

## Architecture Overview

### Current (v1.0) → Future (v2.0)

```
Current:                          Future:
┌──────────────┐                 ┌────────────────────────────┐
│  CLI Only    │                 │  Multi-Interface           │
│              │      →          │  CLI + API + WebSocket     │
│  Monolithic  │                 ├────────────────────────────┤
│              │                 │  Event Bus (Redis)         │
│  Single Node │                 ├────────────────────────────┤
│              │                 │  Plugin System             │
│  File Output │                 ├────────────────────────────┤
└──────────────┘                 │  Worker Pool (N nodes)     │
                                 ├────────────────────────────┤
                                 │  Multi-DB (PG + Redis      │
                                 │  + ClickHouse + Neo4j)     │
                                 └────────────────────────────┘
```

---

## 1. Plugin System

### Architecture

```
Plugin Manager
├── Discovery (scan plugin directories)
├── Loading (dynamic import)
├── Validation (config schema)
└── Execution (async orchestration)

Plugin Types
├── DomainExtractorPlugin (extract from new sources)
├── FilterPlugin (custom filtering)
├── EnrichmentPlugin (add metadata)
└── OutputPlugin (custom output formats)
```

### Example: JavaScript Domain Extractor

```python
from tlsxtractor.plugins.base import DomainExtractorPlugin

class JSExtractor(DomainExtractorPlugin):
    async def extract_domains(self, context):
        # Fetch JavaScript files
        js_files = await self.fetch_js_files(context.sni)

        # Extract domains using regex
        domains = []
        for js in js_files:
            domains.extend(self.parse_domains(js))

        return ExtractionResult(
            domains=domains,
            confidence=0.8,
            source="js_extractor"
        )
```

### Plugin Discovery

Plugins loaded from:
- `./plugins/core/` - Built-in plugins
- `./plugins/community/` - Community plugins
- `~/.tlsxtractor/plugins/` - User plugins
- Custom paths via config

### Plugin Configuration

```yaml
plugins:
  autoload:
    - certificate_extractor
    - csp_extractor
    - js_extractor

  config:
    js_extractor:
      max_file_size: 5242880
      timeout: 30
```

**Benefits:**
- Extend functionality without modifying core
- Community can contribute extractors
- Easy to enable/disable features
- Isolated failure domains

---

## 2. Configuration Management

### Multi-Source Configuration

```
Priority (highest to lowest):
1. CLI Arguments
2. Environment Variables
3. Config File (YAML/TOML)
4. Defaults
```

### Configuration Schema (Pydantic)

```python
class ScanningConfig(BaseModel):
    threads: int = Field(10, ge=1, le=1000)
    rate_limit: float = Field(10.0, gt=0)
    timeout: int = Field(5, ge=1)

class TLSXtractorConfig(BaseModel):
    scanning: ScanningConfig
    dns: DNSConfig
    database: DatabaseConfig
    api: APIConfig
```

### Example Configuration (config.yml)

```yaml
app:
  environment: production
  log_level: info

scanning:
  performance:
    threads: 50
    rate_limit: 100.0
    timeout: 10

  features:
    fetch_csp: true
    extract_javascript: true

dns:
  cache:
    enabled: true
    maxsize: 50000
    ttl: 7200

database:
  postgres:
    enabled: true
    host: ${DB_HOST}
    password: ${DB_PASSWORD}

  redis:
    enabled: true
    url: redis://localhost:6379

api:
  enabled: true
  port: 8000
  cors_origins:
    - https://dashboard.company.com

distributed:
  enabled: true
  broker_url: redis://localhost:6379/1
  workers: 10
```

### Environment Variables

```bash
# Override any config value
export TLSXTRACTOR_SCANNING_THREADS=100
export TLSXTRACTOR_DNS_CACHE_MAXSIZE=100000

# Secrets from environment
export DB_PASSWORD=secret123
export API_KEY=key123
```

### Hot Reloading

```python
config_manager = ConfigurationManager(watch=True)

# Register callback
def on_config_reload(new_config):
    logger.info("Config reloaded!")
    update_thread_pool(new_config.scanning.threads)

config_manager.on_reload(on_config_reload)
```

**Benefits:**
- Single source of truth
- Environment-specific configs
- Secrets from environment
- Hot reload without restart
- Type-safe with validation

---

## 3. Event Bus

### Architecture

```
Event Sources              Event Bus              Event Handlers
┌─────────────┐          ┌──────────┐           ┌──────────────┐
│ Scanner     │───┐      │          │      ┌───→│ Metrics      │
│ DNS Resolver│───┼─────→│  Redis   │──────┼───→│ Webhooks     │
│ Plugins     │───┘      │  Pub/Sub │      └───→│ Notifications│
└─────────────┘          └──────────┘           └──────────────┘
```

### Event Types

```python
class EventType(Enum):
    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    # Discovery events
    DOMAIN_DISCOVERED = "domain.discovered"
    CERTIFICATE_FOUND = "certificate.found"
    VULNERABILITY_DETECTED = "vulnerability.detected"

    # System events
    WORKER_STARTED = "worker.started"
    WORKER_STOPPED = "worker.stopped"
    PLUGIN_LOADED = "plugin.loaded"
```

### Event Model

```python
@dataclass
class Event:
    id: str
    type: EventType
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    metadata: Dict[str, Any] = None
```

### Event Bus Implementation

```python
class EventBus:
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
        self.handlers = defaultdict(list)

    async def publish(self, event: Event):
        """Publish event to all subscribers."""
        channel = f"events:{event.type.value}"
        await self.redis.publish(
            channel,
            json.dumps(event.to_dict())
        )

    async def subscribe(self, event_type: EventType, handler):
        """Subscribe to events."""
        self.handlers[event_type].append(handler)

        # Start listener
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(f"events:{event_type.value}")

        async for message in pubsub.listen():
            if message['type'] == 'message':
                event = Event.from_dict(json.loads(message['data']))
                for handler in self.handlers[event_type]:
                    await handler(event)
```

### Usage Examples

**Emit Events:**
```python
# In scanner
await event_bus.publish(Event(
    id=uuid4(),
    type=EventType.DOMAIN_DISCOVERED,
    timestamp=datetime.now(),
    source="scanner",
    data={
        "domain": "api.example.com",
        "ip": "1.2.3.4",
        "confidence": 0.95
    }
))
```

**Subscribe to Events:**
```python
# Metrics handler
async def update_metrics(event: Event):
    metrics.domains_discovered.inc()
    metrics.last_discovery_time.set(time.time())

await event_bus.subscribe(
    EventType.DOMAIN_DISCOVERED,
    update_metrics
)
```

**Webhooks:**
```yaml
events:
  subscriptions:
    - event: scan.completed
      webhook: https://api.company.com/scan-complete

    - event: vulnerability.detected
      webhook: https://security.company.com/alert
      pagerduty: true
```

**WebSocket Streaming:**
```python
# Web UI can subscribe to real-time events
@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()

    async def send_event(event: Event):
        await websocket.send_json(event.to_dict())

    await event_bus.subscribe(
        EventType.DOMAIN_DISCOVERED,
        send_event
    )
```

**Benefits:**
- Real-time monitoring
- Decouple components
- Easy integration via webhooks
- Audit trail
- Reactive architecture

---

## 4. Distributed Scanning

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Coordinator Node                    │
│  ┌──────────────────────────────────────────┐  │
│  │  Task Queue (Celery + Redis)             │  │
│  │  • Split targets into chunks              │  │
│  │  • Distribute to workers                  │  │
│  │  • Aggregate results                      │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
              │         │         │
    ┌─────────┴─────┬───┴───┬─────┴─────┐
    │               │       │           │
┌────────┐     ┌────────┐ ┌────────┐ ┌────────┐
│Worker 1│     │Worker 2│ │Worker 3│ │Worker N│
│  • Scan│     │  • Scan│ │  • Scan│ │  • Scan│
│  • DNS │     │  • DNS │ │  • DNS │ │  • DNS │
│  • Cache│    │  • Cache│ │  • Cache│ │  • Cache│
└────────┘     └────────┘ └────────┘ └────────┘
```

### Celery Integration

```python
# Celery app
from celery import Celery

app = Celery(
    'tlsxtractor',
    broker='redis://localhost:6379/1',
    backend='redis://localhost:6379/2'
)

@app.task
async def scan_target(ip: str, port: int, sni: str = None):
    """Scan a single target (distributed task)."""
    scanner = TLSScanner()
    result = await scanner.scan_target(ip, port, sni)
    return result.to_dict()

@app.task
async def scan_cidr(cidr: str):
    """Scan CIDR range (coordinator task)."""
    # Split into chunks
    ips = list(ipaddress.ip_network(cidr).hosts())

    # Create tasks for each IP
    tasks = [
        scan_target.delay(str(ip), 443)
        for ip in ips
    ]

    # Wait for all results
    results = [task.get() for task in tasks]

    # Aggregate and store
    await store_results(cidr, results)

    return {"scanned": len(results)}
```

### Coordinator Implementation

```python
class ScanCoordinator:
    """Coordinates distributed scans across workers."""

    def __init__(self, broker_url: str):
        self.celery = Celery(broker=broker_url)
        self.active_scans = {}

    async def start_scan(
        self,
        targets: List[str],
        config: ScanConfig
    ) -> str:
        """Start distributed scan."""
        scan_id = uuid4()

        # Split targets into batches
        batches = self.create_batches(targets, batch_size=1000)

        # Create tasks
        tasks = []
        for batch in batches:
            task = self.celery.send_task(
                'scan_batch',
                args=[batch, config.to_dict()]
            )
            tasks.append(task)

        # Track scan
        self.active_scans[scan_id] = {
            'tasks': tasks,
            'total': len(targets),
            'started': datetime.now()
        }

        return scan_id

    async def get_scan_status(self, scan_id: str) -> Dict:
        """Get scan progress."""
        scan = self.active_scans[scan_id]

        completed = sum(1 for t in scan['tasks'] if t.ready())
        failed = sum(1 for t in scan['tasks'] if t.failed())

        return {
            'scan_id': scan_id,
            'total_tasks': len(scan['tasks']),
            'completed': completed,
            'failed': failed,
            'progress': completed / len(scan['tasks']) * 100,
            'elapsed': (datetime.now() - scan['started']).total_seconds()
        }
```

### Worker Deployment

**Docker Compose:**
```yaml
version: '3.8'

services:
  # Redis (broker + backend)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  # Coordinator
  coordinator:
    image: tlsxtractor:2.0
    command: coordinator
    depends_on:
      - redis
    environment:
      - BROKER_URL=redis://redis:6379/1
      - MODE=coordinator

  # Workers (scale horizontally)
  worker:
    image: tlsxtractor:2.0
    command: worker
    depends_on:
      - redis
      - coordinator
    environment:
      - BROKER_URL=redis://redis:6379/1
      - MODE=worker
      - CONCURRENCY=4
    deploy:
      replicas: 10  # 10 workers
```

**Kubernetes:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tlsxtractor-worker
spec:
  replicas: 50  # 50 worker pods
  selector:
    matchLabels:
      app: tlsxtractor-worker
  template:
    metadata:
      labels:
        app: tlsxtractor-worker
    spec:
      containers:
      - name: worker
        image: tlsxtractor:2.0
        command: ["celery", "worker"]
        env:
        - name: BROKER_URL
          value: "redis://redis-service:6379/1"
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
```

**Benefits:**
- Scan millions of IPs in parallel
- Horizontal scaling (add more workers)
- Fault tolerance (worker failures don't stop scan)
- Resource optimization
- Cloud-native deployment

---

## 5. Web API

### API Architecture

```
┌─────────────────────────────────────────┐
│           FastAPI Application            │
├─────────────────────────────────────────┤
│  REST API  │  GraphQL  │  WebSocket    │
├─────────────────────────────────────────┤
│  Authentication & Authorization          │
│  (API Keys, OAuth, JWT)                  │
├─────────────────────────────────────────┤
│  Rate Limiting                           │
│  (per user/API key)                      │
├─────────────────────────────────────────┤
│  Business Logic                          │
│  (Scan orchestration, queries)           │
└─────────────────────────────────────────┘
```

### REST API Endpoints

**Scan Management:**
```
POST   /api/v1/scans              Create new scan
GET    /api/v1/scans              List scans
GET    /api/v1/scans/{id}         Get scan details
DELETE /api/v1/scans/{id}         Cancel scan
GET    /api/v1/scans/{id}/results Get scan results
POST   /api/v1/scans/{id}/export  Export results
```

**Domain Queries:**
```
GET    /api/v1/domains                  List domains
GET    /api/v1/domains/{domain}         Domain details
GET    /api/v1/domains/{domain}/history History
POST   /api/v1/domains/search           Search domains
```

**Analytics:**
```
GET    /api/v1/analytics/certificates   Certificate stats
GET    /api/v1/analytics/domains        Domain stats
GET    /api/v1/analytics/trends         Trends
POST   /api/v1/analytics/graph          Domain graph
```

**System:**
```
GET    /api/v1/health                   Health check
GET    /api/v1/metrics                  Prometheus metrics
GET    /api/v1/config                   Configuration
GET    /api/v1/plugins                  Installed plugins
```

### FastAPI Implementation

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import List, Optional
import asyncio

app = FastAPI(
    title="TLSXtractor API",
    version="2.0.0",
    description="TLS reconnaissance and domain extraction API"
)

# Models
class ScanRequest(BaseModel):
    targets: List[str]
    config: Optional[ScanConfig] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    targets_count: int
    started_at: datetime

class DomainInfo(BaseModel):
    domain: str
    first_seen: datetime
    last_seen: datetime
    ips: List[str]
    certificates: List[str]

# Security
security = HTTPBearer()

async def verify_api_key(credentials = Depends(security)):
    api_key = credentials.credentials
    # Verify API key
    if not is_valid_api_key(api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

# Endpoints
@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """Create a new scan."""
    coordinator = ScanCoordinator()
    scan_id = await coordinator.start_scan(
        targets=request.targets,
        config=request.config
    )

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        targets_count=len(request.targets),
        started_at=datetime.now()
    )

@app.get("/api/v1/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get scan status and details."""
    coordinator = ScanCoordinator()
    status = await coordinator.get_scan_status(scan_id)
    return status

@app.get("/api/v1/domains/{domain}", response_model=DomainInfo)
async def get_domain(
    domain: str,
    api_key: str = Depends(verify_api_key)
):
    """Get domain information."""
    db = get_database()
    domain_info = await db.get_domain(domain)

    if not domain_info:
        raise HTTPException(status_code=404, detail="Domain not found")

    return domain_info

@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: str
):
    """WebSocket endpoint for real-time scan progress."""
    await websocket.accept()

    async def send_update(event: Event):
        if event.data.get('scan_id') == scan_id:
            await websocket.send_json({
                'progress': event.data['progress'],
                'domains_found': event.data['domains_found']
            })

    await event_bus.subscribe(EventType.SCAN_PROGRESS, send_update)
```

### GraphQL API

```python
import strawberry
from strawberry.fastapi import GraphQLRouter

@strawberry.type
class Domain:
    name: str
    first_seen: datetime
    ips: List[str]

    @strawberry.field
    async def certificates(self) -> List[Certificate]:
        return await get_certificates_for_domain(self.name)

@strawberry.type
class Query:
    @strawberry.field
    async def domains(
        self,
        search: Optional[str] = None,
        limit: int = 100
    ) -> List[Domain]:
        return await search_domains(search, limit)

    @strawberry.field
    async def domain(self, name: str) -> Optional[Domain]:
        return await get_domain(name)

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def start_scan(
        self,
        targets: List[str]
    ) -> str:
        return await create_scan(targets)

schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")
```

### API Documentation

Auto-generated with FastAPI:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI spec: `http://localhost:8000/openapi.json`

**Benefits:**
- Programmatic access
- Easy integration
- Real-time updates via WebSocket
- Flexible queries with GraphQL
- Auto-generated documentation

---

## 6. Advanced Analytics

### Certificate Chain Analysis

```python
class CertificateChainAnalyzer:
    """Analyze certificate chains and trust paths."""

    async def analyze_chain(
        self,
        certificate_der: bytes
    ) -> ChainAnalysis:
        """Analyze certificate chain."""
        cert = x509.load_der_x509_certificate(certificate_der)

        chain = []
        current = cert

        # Build chain
        while current:
            chain.append(current)
            issuer = await self.fetch_issuer(current)
            if issuer == current:  # Self-signed
                break
            current = issuer

        return ChainAnalysis(
            chain_length=len(chain),
            certificates=chain,
            root_ca=chain[-1] if chain else None,
            is_valid=self.verify_chain(chain),
            trust_path=self.build_trust_path(chain)
        )

    def verify_chain(self, chain: List[Certificate]) -> bool:
        """Verify certificate chain validity."""
        for i in range(len(chain) - 1):
            if not self.verify_signature(chain[i], chain[i+1]):
                return False
        return True
```

### Domain Relationship Graphs (Neo4j)

```python
from neo4j import AsyncGraphDatabase

class DomainGraphAnalyzer:
    """Build and analyze domain relationship graphs."""

    def __init__(self, neo4j_uri: str):
        self.driver = AsyncGraphDatabase.driver(neo4j_uri)

    async def add_domain_relationship(
        self,
        source_domain: str,
        target_domain: str,
        relationship_type: str
    ):
        """Add domain relationship to graph."""
        async with self.driver.session() as session:
            await session.run("""
                MERGE (s:Domain {name: $source})
                MERGE (t:Domain {name: $target})
                MERGE (s)-[r:RELATES_TO {type: $type}]->(t)
            """, source=source_domain, target=target_domain, type=relationship_type)

    async def get_domain_cluster(
        self,
        domain: str,
        max_depth: int = 3
    ) -> List[str]:
        """Get all related domains up to max_depth."""
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (start:Domain {name: $domain})
                CALL apoc.path.subgraphAll(start, {
                    maxLevel: $max_depth,
                    relationshipFilter: 'RELATES_TO'
                })
                YIELD nodes
                RETURN [n IN nodes | n.name] AS domains
            """, domain=domain, max_depth=max_depth)

            record = await result.single()
            return record['domains'] if record else []
```

### Visualization API

```python
@app.get("/api/v1/analytics/graph/{domain}")
async def get_domain_graph(
    domain: str,
    depth: int = 2,
    format: str = "cytoscape"
):
    """Get domain relationship graph."""
    analyzer = DomainGraphAnalyzer()

    # Get related domains
    cluster = await analyzer.get_domain_cluster(domain, depth)

    # Build graph structure
    if format == "cytoscape":
        nodes = [{"data": {"id": d, "label": d}} for d in cluster]
        edges = await analyzer.get_edges(cluster)
        return {"elements": {"nodes": nodes, "edges": edges}}

    elif format == "d3":
        # D3.js format
        nodes = [{"id": d, "name": d} for d in cluster]
        links = await analyzer.get_links(cluster)
        return {"nodes": nodes, "links": links}
```

**Benefits:**
- Deep certificate insights
- Visualize domain relationships
- Identify infrastructure patterns
- Track certificate authorities
- Network topology mapping

---

## Implementation Roadmap

### Phase 1: Foundation (Months 1-2)
**Goal:** Core infrastructure

- ✅ Database schema design
- ✅ Configuration management
- ✅ Plugin system base classes
- ✅ Event bus implementation
- 📊 Deliverables: Working config system, plugin loader

### Phase 2: Distribution (Months 3-4)
**Goal:** Horizontal scaling

- 🔄 Celery integration
- 🔄 Worker implementation
- 🔄 Task distribution
- 🔄 Result aggregation
- 📊 Deliverables: Distributed scanning with 10x throughput

### Phase 3: API Layer (Months 5-6)
**Goal:** Programmatic access

- 🔄 FastAPI REST endpoints
- 🔄 GraphQL implementation
- 🔄 WebSocket real-time
- 🔄 Authentication/authorization
- 📊 Deliverables: Full-featured Web API

### Phase 4: Analytics (Months 7-8)
**Goal:** Intelligence layer

- 🔄 Certificate chain analysis
- 🔄 Neo4j graph database
- 🔄 Relationship tracking
- 🔄 Visualization endpoints
- 📊 Deliverables: Advanced analytics dashboard

### Phase 5: Polish & Production (Months 9-10)
**Goal:** Production-ready release

- 🔄 Performance optimization
- 🔄 Security hardening
- 🔄 Documentation
- 🔄 Migration tools
- 📊 Deliverables: TLSXtractor 2.0 GA

---

## Success Metrics

### Performance
- ✅ **10x throughput** via distributed workers
- ✅ **50% faster DNS** with optimized caching
- ✅ **Sub-second API response** for queries

### Scalability
- ✅ **1M+ IPs per hour** scanning capacity
- ✅ **100+ concurrent scans** support
- ✅ **Horizontal scaling** to 1000+ workers

### Usability
- ✅ **< 5 minutes** to first scan (new users)
- ✅ **Zero-downtime** config updates
- ✅ **Real-time** progress tracking

### Integration
- ✅ **API-first** design
- ✅ **Webhook** integrations
- ✅ **GraphQL** flexible queries

---

## Migration Strategy

### v1.0 → v2.0 Migration

**Backward Compatibility:**
- ✅ CLI interface remains unchanged
- ✅ Output format compatible
- ✅ Config files optional (CLI args still work)

**Migration Path:**
1. Install v2.0
2. Run existing CLI commands (no changes needed)
3. Optionally migrate to config files
4. Enable advanced features as needed

**Data Migration:**
```bash
# Export v1.0 results
tlsxtractor export --format v2

# Import to v2.0 database
tlsxtractor import --file results_v1.json
```

---

## Conclusion

This architecture transforms TLSXtractor into an enterprise-grade platform while maintaining simplicity for single-user CLI usage. The modular design allows incremental adoption of advanced features.

**Next Steps:**
1. Review and approve architecture
2. Begin Phase 1 implementation
3. Set up development environment
4. Create detailed implementation specs

**Timeline:** 10 months to v2.0 GA
**Resources:** 2-3 engineers
**Investment:** High value for enterprise deployments

---

**Document Status:** Ready for Review
**Last Updated:** November 10, 2025
**Version:** 1.0
