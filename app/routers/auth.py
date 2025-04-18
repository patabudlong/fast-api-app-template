from fastapi import APIRouter, HTTPException, Request, Depends, Security, Form, status, Header
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Annotated
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
import logging
from bson import ObjectId

router = APIRouter(
    prefix="/auth",
    tags=["authentication"]
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Update user models
class UserBase(BaseModel):
    email: EmailStr
    username: str
    first_name: str
    last_name: str
    middle_name: Optional[str] = None
    extension_name: Optional[str] = None  # For suffixes like Jr., Sr., III, etc.

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "6801c4ef6bbe2a30361d3bca",
                "email": "john.doe@example.com",
                "username": "johndoe",
                "first_name": "John",
                "middle_name": "William",
                "last_name": "Doe",
                "extension_name": "Jr.",
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T00:00:00"
            }
        }

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
        if user := await request.app.mongodb.users.find_one({"_id": ObjectId(user_id)}):
            return {
                **user,
                "id": str(user["_id"]),
                "first_name": user.get("first_name", ""),
                "middle_name": user.get("middle_name"),
                "last_name": user.get("last_name", ""),
                "extension_name": user.get("extension_name")
            }
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

class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    middle_name: Optional[str] = None
    extension_name: Optional[str] = None
    username: Optional[str] = Field(default="", description="Optional username, can be empty")

    class Config:
        json_schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "middle_name": "William",
                "extension_name": "Jr.",
                "username": ""
            }
        }

@router.put("/users/{user_id}", 
    response_model=UserResponse,
    summary="Update user details",
    description="Update user profile information. Requires authentication.",
    responses={
        200: {
            "description": "User updated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": "6801c4ef6bbe2a30361d3bca",
                        "email": "john.doe@example.com",
                        "username": "",
                        "first_name": "John",
                        "middle_name": "William",
                        "last_name": "Doe",
                        "extension_name": "Jr.",
                        "created_at": "2024-01-01T00:00:00",
                        "updated_at": "2024-01-01T00:00:00"
                    }
                }
            }
        },
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden - Can only update own profile"},
        404: {"description": "User not found"}
    }
)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    request: Request,
    token: Annotated[HTTPAuthorizationCredentials, Security(security)]
):
    """
    Update user profile information
    
    Args:
        user_id: ID of user to update
        user_update: Updated user information
        token: Bearer token for authentication
        
    Returns:
        Updated user information
        
    Raises:
        401: Invalid token
        403: Not authorized to update this user
        404: User not found
    """
    try:
        # Verify token and get user email
        credentials = token.credentials
        try:
            payload = jwt.decode(credentials, SECRET_KEY, algorithms=[ALGORITHM])
            token_email = payload.get("sub")
            if not token_email:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Get current user
        current_user = await request.app.mongodb.users.find_one({"email": token_email})
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Check if user is updating their own profile
        if str(current_user["_id"]) != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only update own profile"
            )

        # Prepare update data
        update_data = {
            k: v for k, v in user_update.dict(exclude_unset=True).items() 
            if v is not None  # Only include non-None values
        }
        
        if not update_data:
            # If no valid updates, return current user data
            return {**current_user, "id": str(current_user["_id"])}

        # Add updated_at timestamp
        update_data["updated_at"] = datetime.utcnow()

        # Update user
        result = await request.app.mongodb.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )

        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or no changes made"
            )

        # Get updated user
        updated_user = await request.app.mongodb.users.find_one({"_id": ObjectId(user_id)})
        return {**updated_user, "id": str(updated_user["_id"])}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating user"
        )