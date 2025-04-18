from fastapi import APIRouter, HTTPException, Request, Depends, Security, Form, status, Header
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Annotated
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
import logging

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

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class TokenHeader:
    def __init__(self, authorization: Annotated[str, Header(description="Bearer token for authentication", example="Bearer eyJhbGciOiJIUzI1...")]):
        self.authorization = authorization

# Define security scheme with description
security = HTTPBearer(
    scheme_name="Authorization",
    description="Bearer token authentication",
    bearerFormat="JWT"
)

logger = logging.getLogger(__name__)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user_id = payload.get("user_id")  # Extract user_id from token
        
        if not email or not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
            
        return {"email": email, "user_id": user_id}
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

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

@router.get("/users/{user_id}", response_model=UserResponse,
    summary="Get user details",
    description="""
    Retrieve user details by ID.
    
    **Authorization Required:**
    - Bearer token must be provided in Authorization header
    - Format: `Bearer your_token_here`
    
    **Parameters:**
    - user_id: The ID of the user to retrieve
    - Authorization: Bearer token in header
    """,
    responses={
        200: {
            "description": "User details retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": "6801c4ef6bbe2a30361d3bca",
                        "email": "user@example.com",
                        "full_name": "John Doe",
                        "created_at": "2024-01-01T00:00:00",
                        "updated_at": "2024-01-01T00:00:00"
                    }
                }
            }
        },
        401: {
            "description": "Missing or invalid token",
            "content": {
                "application/json": {
                    "example": {"detail": "Could not validate credentials"}
                }
            }
        },
        404: {
            "description": "User not found",
            "content": {
                "application/json": {
                    "example": {"detail": "User not found"}
                }
            }
        }
    }
)
async def get_user(
    user_id: str,
    request: Request,
    token: Annotated[HTTPAuthorizationCredentials, Security(security)]
):
    """
    Get user details by ID
    
    Args:
        user_id: User ID to retrieve
        token: Bearer token for authentication
        
    Returns:
        User profile information
        
    Raises:
        401: Invalid or missing token
        404: User not found
        400: Invalid ID format
    """
    try:
        # Verify token
        credentials = token.credentials
        try:
            payload = jwt.decode(credentials, SECRET_KEY, algorithms=[ALGORITHM])
            if not payload.get("sub"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Get user data
        from bson import ObjectId
        if user := await request.app.mongodb.users.find_one({"_id": ObjectId(user_id)}):
            return {**user, "id": str(user["_id"])}
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid ID format"
        )

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
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    error_msg = "Incorrect email or password"
    try:
        # First try to find by email
        user = await request.app.mongodb.users.find_one({"email": username})
        
        if not user:
            # If not found by email, try username
            user = await request.app.mongodb.users.find_one({"username": username})
            
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_msg
            )

        if not pwd_context.verify(password, user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_msg
            )

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": user["email"],
                "email": user["email"],
                "user_id": str(user["_id"])  # Add user_id to token payload
            },
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "Bearer"
        }
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg
        )

@router.post("/change-password", response_model=dict)
async def change_password(
    request: Request,
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    try:
        if not pwd_context.verify(password_data.current_password, current_user["hashed_password"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        new_hashed_password = pwd_context.hash(password_data.new_password)
        
        result = await request.app.mongodb.users.update_one(
            {"_id": current_user["_id"]},
            {
                "$set": {
                    "hashed_password": new_hashed_password,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 1:
            return {"message": "Password updated successfully"}
        raise HTTPException(status_code=500, detail="Failed to update password")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))