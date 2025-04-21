from fastapi import FastAPI
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
import os
from app.routers import auth, users
from datetime import datetime

app = FastAPI(
    title="User Authentication API",
    description="""
    API for user authentication and management.
    
    Features:
    * User registration and login
    * Password management
    * User profile access
    * Email availability checking
    * Health monitoring
    
    All protected endpoints require Bearer token authentication.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

@app.on_event("startup")
async def startup_db_client():
    app.mongodb_client = AsyncIOMotorClient(os.getenv("MONGODB_URL"))
    app.mongodb = app.mongodb_client.fastapi_db
    
    # Drop existing indexes
    await app.mongodb.users.drop_indexes()
    
    # Create unique index only for email
    await app.mongodb.users.create_index("email", unique=True)

@app.get("/health")
async def health_check():
    try:
        # Check MongoDB connection
        await app.mongodb.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow()
        }

# Include both routers
app.include_router(auth.router)
app.include_router(users.router)

@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI!"}

@app.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"item_id": item_id}

@app.get("/search/")
async def search_items(query: str, skip: Optional[int] = 0, limit: Optional[int] = 10):
    return {
        "query": query,
        "skip": skip,
        "limit": limit
    } 