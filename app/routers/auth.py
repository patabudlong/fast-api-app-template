from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt

router = APIRouter(
    prefix="/auth",
    tags=["authentication"]
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = "your-secret-key-keep-it-secret"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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

@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    error_msg = "Incorrect username or password"
    try:
        user = await request.app.mongodb.users.find_one({"username": form_data.username})
        if not user:
            raise HTTPException(status_code=401, detail=error_msg)
        
        if not pwd_context.verify(form_data.password, user["hashed_password"]):
            raise HTTPException(status_code=401, detail=error_msg)

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"]},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        raise HTTPException(status_code=401, detail=error_msg) 