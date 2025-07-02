import os
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bcrypt import hashpw, gensalt, checkpw
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Variáveis de ambiente não configuradas.")

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 📄 Modelos de entrada
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# 🔐 Rota de registro
def query_supabase(endpoint: str, method="GET", data=None, params=""):
    url = f"{SUPABASE_URL}/rest/v1/{endpoint}{params}"
    if method == "GET":
        return requests.get(url, headers=HEADERS)
    elif method == "POST":
        return requests.post(url, headers=HEADERS, json=data)
@app.post("/register")
def register(request: RegisterRequest):
    check = query_supabase("users", params=f"?select=email&email=eq.{request.email}")
    if check.json():
        raise HTTPException(status_code=400, detail="Usuário já registrado.")

    hashed = hashpw(request.password.encode(), gensalt()).decode()
    data = {
        "username": request.username,
        "email": request.email,
        "password_hash": hashed
    }

    insert = query_supabase("users", method="POST", data=data)
    if insert.status_code >= 400:
        raise HTTPException(status_code=500, detail="Erro ao registrar.")

    return {"message": "Usuário registrado com sucesso."}

# 🔓 Rota de login
@app.post("/login")
def login(request: LoginRequest):
    response = query_supabase("users", params=f"?select=*&email=eq.{request.email}")
    users = response.json()
    if users and checkpw(request.password.encode(), users[0]["password_hash"].encode()):
        return {"message": "Login bem-sucedido."}

    raise HTTPException(status_code=401, detail="Credenciais inválidas.")


# ✅ Rota simples de teste
@app.get("/api/data")
def get_data():
    return {"message": "Hello from the backend!"}
