from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from passlib.context import CryptContext
import logging
import random

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

class VerificationDetails(BaseModel):
    is_verified: bool = False
    verification_code: str = Field(default_factory=lambda: str(random.randint(100000, 999999)))
    verification_sent_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    geo_ip: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    created_at: datetime
    updated_at: datetime
    is_verified: bool
    verified_at: Optional[datetime]
    geo_ip: Optional[str]

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
                "updated_at": "2024-01-01T00:00:00",
                "is_verified": False,
                "verified_at": None,
                "geo_ip": "192.168.1.1"
            }
        }

class VerificationRequest(BaseModel):
    email: EmailStr
    code: str

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "code": "123456"
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
        # Check only email exists
        if await request.app.mongodb.users.find_one({"email": user.email}):
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create user document
        user_dict = user.dict()
        
        # Ensure username is empty string if not provided
        if not user_dict.get("username"):
            user_dict["username"] = ""

        # Get client IP
        client_ip = request.client.host

        # Add verification and timestamp details
        verification = VerificationDetails(
            geo_ip=client_ip,
            verification_sent_at=datetime.utcnow()
        )
        
        user_dict.update({
            "hashed_password": pwd_context.hash(user_dict.pop("password")),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_verified": verification.is_verified,
            "verification_code": verification.verification_code,
            "verification_sent_at": verification.verification_sent_at,
            "verified_at": verification.verified_at,
            "geo_ip": verification.geo_ip
        })

        # Insert into database
        result = await request.app.mongodb.users.insert_one(user_dict)
        
        # Get created user
        created_user = await request.app.mongodb.users.find_one({"_id": result.inserted_id})
        
        # TODO: Send verification email with code
        
        return {
            **created_user, 
            "id": str(created_user["_id"]),
            # Don't expose verification code in response
            "verification_code": None if "verification_code" in created_user else None
        }

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/verify", 
    response_model=UserResponse,
    summary="Verify user email",
    description="Verify user email with the 6-digit code",
    responses={
        200: {
            "description": "Email verified successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": "6801c4ef6bbe2a30361d3bca",
                        "email": "user@example.com",
                        "username": "",
                        "first_name": "John",
                        "last_name": "Doe",
                        "is_verified": True,
                        "verified_at": "2024-01-01T00:00:00",
                        "geo_ip": "192.168.1.1"
                    }
                }
            }
        },
        400: {
            "description": "Invalid verification code",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid verification code"}
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
async def verify_email(
    request: Request,
    verification: VerificationRequest
):
    """
    Verify user email with verification code
    
    Args:
        verification: Email and verification code
        
    Returns:
        Updated user information
        
    Raises:
        404: User not found
        400: Invalid verification code
    """
    try:
        # Find user by email
        user = await request.app.mongodb.users.find_one({"email": verification.email})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        # Check if already verified
        if user.get("is_verified"):
            return {**user, "id": str(user["_id"])}
            
        # Check verification code
        if user.get("verification_code") != verification.code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code"
            )
            
        # Update verification status
        now = datetime.utcnow()
        update_result = await request.app.mongodb.users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "is_verified": True,
                    "verified_at": now,
                    "updated_at": now
                }
            }
        )
        
        if update_result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update verification status"
            )
            
        # Get updated user
        updated_user = await request.app.mongodb.users.find_one({"_id": user["_id"]})
        return {**updated_user, "id": str(updated_user["_id"])}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during verification"
        ) 