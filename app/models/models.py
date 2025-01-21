from datetime import datetime , timedelta
from typing import List, Optional, Dict , Tuple , Any
from enum import Enum
from pydantic import (
    BaseModel,
    Field,
    EmailStr,
    HttpUrl,
    constr,
    conint,
    validator,
    ConfigDict,
)
from typing_extensions import Annotated
from geojson import Point


class ScamType(str, Enum):
    PHISHING = "phishing"
    INVESTMENT = "investment"
    ROMANCE = "romance"
    TECH_SUPPORT = "tech_support"
    CRYPTO = "cryptocurrency"
    IDENTITY_THEFT = "identity_theft"
    ADVANCE_FEE = "advance_fee"
    OTHER = "other"


class ScammerStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNDER_INVESTIGATION = "under_investigation"
    CONFIRMED = "confirmed"
    BLOCKED = "blocked"


class GeoPoint(BaseModel):
    type: str = Field("Point" ,description="Type of the GeoJSON object")
    coordinates: Tuple[float, float] = Field(..., description="longitude, latitude")

    @validator("coordinates")
    def validate_coordinates(cls, v):
        longitude, latitude = v
        if not -180 <= longitude <= 180:
            raise ValueError("Longitude must be between -180 and 180")
        if not -90 <= latitude <= 90:
            raise ValueError("Latitude must be between -90 and 90")
        return v


class Location(BaseModel):
    country: str = Field(..., min_length=2, max_length=100)
    city: Optional[str] = Field(None, max_length=100)
    coordinates: Optional[GeoPoint] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "country": "United States",
                "city": "New York",
                "coordinates": {
                    "type": "Point",
                    "coordinates": [-73.935242, 40.730610]
                }
            }
        }
    )


class VictimReport(BaseModel):
    report_id: str = Field(..., description="Unique identifier for the report")
    date_reported: datetime = Field(default_factory=datetime.utcnow)
    amount_lost: Optional[float] = Field(None, ge=0)
    currency: Optional[str] = Field(None, max_length=3)
    scam_type: ScamType
    description: Optional[str] = Field(None, max_length=2000)
    evidence_urls: List[HttpUrl] = Field(default_factory=list)
    contact_method: Optional[str] = Field(None, max_length=100)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "report_id": "REP123456",
                "amount_lost": 1000.00,
                "currency": "USD",
                "scam_type": "phishing",
                "description": "Received phishing email claiming to be from bank"
            }
        }
    )


class ScammerModel(BaseModel):
    id: str = Field(default=None, alias="_id")
    email: EmailStr = Field(..., description="Primary email address used by scammer")
    email_aliases: List[EmailStr] = Field(default_factory=list)
    phone_numbers: List[str] = Field(
        default_factory=list,
        description="List of phone numbers associated with the scammer"
    )
    ip_addresses: List[str] = Field(
        default_factory=list,
        description="List of IP addresses used by the scammer"
    )
    aliases: List[str] = Field(
        default_factory=list,
        description="Known aliases or names used by the scammer"
    )
    websites: List[HttpUrl] = Field(
        default_factory=list,
        description="Websites associated with scam operations"
    )
    scam_types: List[ScamType] = Field(
        ...,
        description="Types of scams perpetrated"
    )
    reported_locations: List[Location] = Field(
        default_factory=list,
        description="Locations where the scammer has been reported"
    )
    victims: List[VictimReport] = Field(
        default_factory=list,
        description="Reports from victims"
    )
    status: ScammerStatus = Field(
        default=ScammerStatus.UNDER_INVESTIGATION,
        description="Current status of the scammer"
    )
    threat_level: conint(ge=1, le=5) = Field(
        ...,
        description="Assessed threat level from 1 (lowest) to 5 (highest)"
    )
    first_reported: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    # Additional fields
    total_reported_losses: float = Field(
        default=0.0,
        description="Total reported financial losses across all victims"
    )
    known_associates: List[str] = Field(
        default_factory=list,
        description="IDs of other known scammers they work with"
    )
    notes: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Investigation notes and updates"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Custom tags for categorization"
    )
    evidence_files: List[str] = Field(
        default_factory=list,
        description="References to stored evidence files"
    )

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "email": "scammer@example.com",
                "phone_numbers": ["+1234567890"],
                "scam_types": ["phishing", "investment"],
                "threat_level": 4
            }
        }

    @validator("last_updated", always=True)
    def update_timestamp(cls, v):
        return datetime.utcnow()

# JWT AUTHENTICATION STUFF

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password : str

class UserRegistration(BaseModel):
    username : str
    email : EmailStr
    password : str





# MongoDB indexes configuration
indexes = [
    {
        "fields": [("email", 1)],
        "unique": True,
    },
    {
        "fields": [("phone_numbers", 1)],
    },
    {
        "fields": [("ip_addresses", 1)],
    },
    {
        "fields": [("status", 1), ("threat_level", -1)],
    },
    {
        "fields": [("scam_types", 1)],
    },
    {
        "fields": [("reported_locations.country", 1)],
    },
    {
        "fields": [("last_updated", -1)],
    },
]
