from datetime import timedelta , datetime
from typing import Union
from jose import jwt , JWTError
from passlib.context import CryptContext

from .config import settings

def create_access_token(data : dict , expires_delta : Union[timedelta , None ] = None) :
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp" : expire})
    return jwt.encode(to_encode , settings.APP_SECRET_KEY , algorithm = settings.JWT_ALGORITHM)

def verify_token(token : str , credentials_exception) :
    try :
        payload = jwt.decode(token , settings.APP_SECRET_KEY , algorithms = [settings.JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None :
            raise credentials_exception
        return username
    except JWTError :
        raise credentials_exception


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)
