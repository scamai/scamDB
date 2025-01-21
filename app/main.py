from dotenv import load_dotenv
load_dotenv()
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOGGER = logging.getLogger(__name__)
from fastapi import FastAPI , Depends
from .core.config import settings
from .core.dependencies import db
from fastapi.middleware.cors import CORSMiddleware
from .models.models import ScammerModel
from fastapi.exceptions import HTTPException
from bson import ObjectId
from .core.jwt import create_access_token
from .core.auth import authenticate_user, get_current_active_user, get_password_hash
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from .models.models import Token, User , UserRegistration


app = FastAPI(
    title = settings.APP_NAME,
    debug = settings.DEBUG_MODE,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_db_client():
    await db.connect_mongodb()

@app.on_event("shutdown")
async def shutdown_db_client():
    await db.close_mongodb()


# scammer_collection = db.db["scammers"]

@app.post("/scammers/")
async def create_scammer(scammer: ScammerModel):
    collection = db.db["scammers"]
    result = await collection.insert_one(scammer.dict(exclude_unset=True))
    if result.inserted_id:
        return {"id": str(result.inserted_id)}
    raise HTTPException(status_code=400, detail="Failed to create record")



@app.get("/scammers/{scammer_id}")
async def get_scammer(scammer_id: str):
    collection = db.db["scammers"]
    try :
        object_id = ObjectId(scammer_id)
    except Exception as e :
        raise HTTPException(status_code=400, detail= f"Invalid ID {e}")
    scammer = await collection.find_one({"_id": object_id})
    if not scammer:
        raise HTTPException(status_code=404, detail="Scammer not found")
    scammer["_id"] = str(scammer["_id"])
    return ScammerModel(**scammer)


@app.get("/health")
async def health_check():
    try:
        await db.db.command("ping")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": str(e)}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.post('/register', status_code = 201)
async def register_user(user: UserRegistration):
    collection = db.db['users']
    existing_user = await collection.find_one({"$or": [{"username": user.username}, {"email": user.email}]})
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        )

    # Hash the password
    hashed_password = get_password_hash(user.password)

    # Insert user into the database
    user_dict = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password,
        "disabled": False  # Default to active user
    }
    result = await collection.insert_one(user_dict)
    if result.inserted_id:
        return {"id": str(result.inserted_id), "username": user.username, "email": user.email}

    raise HTTPException(
        status_code=500,
        detail="Failed to register user"
    )
