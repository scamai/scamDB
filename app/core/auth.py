from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .dependencies import db
from bson.objectid import ObjectId
from .jwt import create_access_token, verify_token , verify_password , get_password_hash
from ..models.models import UserInDB

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



def get_user(username: str):
    user_collection = db.db["users"]
    user_data = user_collection.find_one({"username" : username})
    if user_data:
        return UserInDB(**user_data)
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user



async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = verify_token(token, credentials_exception)
    user = get_user(username)
    if user is None :
        raise credentials_exception
    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
