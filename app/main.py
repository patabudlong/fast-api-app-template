from fastapi import FastAPI
from typing import Optional

app = FastAPI(
    title="My FastAPI App",
    description="A simple FastAPI application",
    version="1.0.0"
)

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