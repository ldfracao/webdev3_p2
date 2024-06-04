from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.hash import bcrypt
import jwt
import requests
from datetime import datetime, timedelta

app = FastAPI()
app.mount("/views", StaticFiles(directory="views"), name="views")
db_client = AsyncIOMotorClient("mongodb://localhost:27017")
db = db_client["my_database"]
users_collection = db["users"]

class User(BaseModel):
    username: str
    password: str
class TokenData(BaseModel):
    username: str

async def get_user(username: str):
    user = await users_collection.find_one({"username": username})
    return user

async def create_user(user: User):
    existing_user = await get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = bcrypt.hash(user.password)
    new_user = {"username": user.username, "password": hashed_password}
    await users_collection.insert_one(new_user)
    return new_user

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"

class TokenBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(TokenBearer, self).__init__(auto_error=auto_error)
    async def __call__(self, request: Request) -> str:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if not credentials.scheme.lower() == "bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

token_bearer = TokenBearer(auto_error=False)

@app.get("/")
def root():
    return RedirectResponse(url="views/register.html", status_code=302)

@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...)):
    user = User(username=username, password=password)
    new_user = await create_user(user)
    payload = {"username": new_user["username"], "exp": datetime.utcnow() + timedelta(minutes=30)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return RedirectResponse(url="/views/login.html", status_code=302)

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = User(username=username, password=password)
    existing_user = await get_user(user.username)
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    if not bcrypt.verify(user.password, existing_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    payload = {"username": existing_user["username"], "exp": datetime.utcnow() + timedelta(minutes=30)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return RedirectResponse(url="/views/main.html", status_code=302, headers={"Authorization": f"Bearer {token}"})

@app.get("/search")
async def search_pokemons(search: str):
    url = f"https://pokeapi.co/api/v2/pokemon/{search}"
    response = requests.get(url)
    if response.status_code == 200:
        pokemon_data = response.json()
        return JSONResponse(content={"name": pokemon_data["name"], "id": pokemon_data["id"]}, status_code=200)
    else:
        return JSONResponse(content={"error": "Pokémon not found"}, status_code=404)

async def get_token(token: str = Depends(token_bearer)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/cep")
async def get_address_by_cep(cep: str):
    url = f"https://viacep.com.br/ws/{cep}/json/"
    response = requests.get(url)
    if response.status_code == 200:
        address_data = response.json()
        if "erro" not in address_data:
            return JSONResponse(content=address_data, status_code=200)
        else:
            return JSONResponse(content={"error": "CEP not found"}, status_code=404)
    else:
        return JSONResponse(content={"error": "Failed to fetch data"}, status_code=response.status_code)

@app.get("/protected")
async def protected_route(token_data: TokenData = Depends(get_token)):
    user = await get_user(token_data.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"message": "This is a protected route"}
