from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext

router = APIRouter(
    prefix="/auth",
    tags=["authentication"]
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    password: str
    disabled: Optional[bool] = False

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    disabled: bool
    created_at: datetime
    updated_at: datetime

@router.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate, request: Request):
    user_dict = user.dict()
    # Hash the password
    user_dict["hashed_password"] = pwd_context.hash(user_dict.pop("password"))
    user_dict["created_at"] = datetime.utcnow()
    user_dict["updated_at"] = datetime.utcnow()
    
    try:
        result = await request.app.mongodb.users.insert_one(user_dict)
        created_user = await request.app.mongodb.users.find_one({"_id": result.inserted_id})
        return {**created_user, "id": str(created_user["_id"])}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, request: Request):
    from bson import ObjectId
    try:
        if user := await request.app.mongodb.users.find_one({"_id": ObjectId(user_id)}):
            return {**user, "id": str(user["_id"])}
        raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid ID format")

@router.get("/users", response_model=List[UserResponse], tags=["users"])
async def get_all_users(request: Request):
    try:
        users = []
        cursor = request.app.mongodb.users.find({})
        async for document in cursor:
            users.append({**document, "id": str(document["_id"])})
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 