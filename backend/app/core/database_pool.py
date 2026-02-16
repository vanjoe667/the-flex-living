import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import QueuePool
import logging
from ..config import settings

logger = logging.getLogger(__name__)

class DatabasePool:
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.engine = None
            self.session_factory = None
            self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize database connection pool (idempotent)"""
        if self._initialized:
            return
        
        async with self._lock:
            if self._initialized:  # Double-check after acquiring lock
                return
            
            try:
                database_url = f"postgresql+asyncpg://{settings.supabase_db_user}:{settings.supabase_db_password}@{settings.supabase_db_host}:{settings.supabase_db_port}/{settings.supabase_db_name}"
                
                self.engine = create_async_engine(
                    database_url,
                    poolclass=QueuePool,
                    pool_size=20,
                    max_overflow=30,
                    pool_pre_ping=True,
                    pool_recycle=3600,
                    echo=False
                )
                
                self.session_factory = async_sessionmaker(
                    bind=self.engine,
                    class_=AsyncSession,
                    expire_on_commit=False
                )
                
                self._initialized = True
                logger.info("✅ Database connection pool initialized")
                
            except Exception as e:
                logger.error(f"❌ Database pool initialization failed: {e}")
                raise
    
    async def close(self):
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()
            self._initialized = False
    
    def get_session(self):
        """Get database session from pool"""
        if not self._initialized or not self.session_factory:
            raise Exception("Database pool not initialized. Call initialize() first.")
        return self.session_factory()

# Global singleton instance
db_pool = DatabasePool()