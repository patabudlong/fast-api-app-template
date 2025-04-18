from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from passlib.context import CryptContext
import logging

# Create the router instance
router = APIRouter(
    prefix="/users",
    tags=["users"]
)

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class EmailCheck(BaseModel):
    email: EmailStr

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }

class EmailCheckResponse(BaseModel):
    exists: bool
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "exists": True,
                "message": "Email is already registered"
            }
        }

class UserBase(BaseModel):
    email: EmailStr
    username: Optional[str] = Field(default="", description="Optional username, can be empty")
    first_name: str
    last_name: str
    middle_name: Optional[str] = None
    extension_name: Optional[str] = None

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
                "username": "",
                "first_name": "John",
                "middle_name": "William",
                "last_name": "Doe",
                "extension_name": "Jr.",
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T00:00:00"
            }
        }

@router.post("/check-email", 
    response_model=EmailCheckResponse,
    summary="Check email availability",
    description="Check if an email address is already registered",
    responses={
        200: {
            "description": "Email check result",
            "content": {
                "application/json": {
                    "examples": {
                        "exists": {
                            "value": {
                                "exists": True,
                                "message": "Email is already registered"
                            }
                        },
                        "not_exists": {
                            "value": {
                                "exists": False,
                                "message": "Email is available"
                            }
                        }
                    }
                }
            }
        },
        422: {
            "description": "Validation Error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email format"
                    }
                }
            }
        }
    }
)
async def check_email(
    request: Request,
    email_data: EmailCheck
):
    """
    Check if an email is already registered in the system
    
    Args:
        email_data: Email to check
        
    Returns:
        JSON object with exists flag and message
    """
    try:
        # Check if email exists
        user = await request.app.mongodb.users.find_one({"email": email_data.email})
        
        if user:
            return {
                "exists": True,
                "message": "Email is already registered"
            }
        
        return {
            "exists": False,
            "message": "Email is available"
        }
        
    except Exception as e:
        logger.error(f"Email check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error checking email availability"
        )

@router.post("/register", 
    response_model=UserResponse,
    summary="Register new user",
    description="Create a new user account. Username is optional and can be empty.",
    responses={
        201: {
            "description": "User created successfully"
        },
        400: {
            "description": "Email already registered"
        }
    }
)
async def register(request: Request, user: UserCreate):
    """
    Register a new user
    
    Args:
        user: User registration data with optional username
        
    Returns:
        Created user information
    """
    try:
        # Check if email exists
        if await request.app.mongodb.users.find_one({"email": user.email}):
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create user document
        user_dict = user.dict()
        
        # Remove username if empty string
        if not user_dict["username"]:
            user_dict["username"] = ""  # Ensure empty string for consistency

        user_dict["hashed_password"] = pwd_context.hash(user_dict.pop("password"))
        user_dict["created_at"] = datetime.utcnow()
        user_dict["updated_at"] = user_dict["created_at"]

        # Insert into database
        result = await request.app.mongodb.users.insert_one(user_dict)
        
        # Get created user
        created_user = await request.app.mongodb.users.find_one({"_id": result.inserted_id})
        return {**created_user, "id": str(created_user["_id"])}

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e)) 