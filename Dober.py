from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from bcrypt import hashpw, gensalt, checkpw

# Configuração do Supabase
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Variáveis de ambiente SUPABASE_URL e SUPABASE_KEY são necessárias.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Inicialização do aplicativo
app = FastAPI()

# Configuração de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de dados
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/register")
def register(request: RegisterRequest):
    response = supabase.table("users").select("email").eq("email", request.email).execute()
    if response.data:
        raise HTTPException(status_code=400, detail="Usuário já registrado.")

    hashed_password = hashpw(request.password.encode(), gensalt()).decode()
    supabase.table("users").insert({
        "username": request.username,
        "email": request.email,
        "password_hash": hashed_password
    }).execute()

    return {"message": "Usuário registrado com sucesso."}

@app.post("/login")
def login(request: LoginRequest):
    response = supabase.table("users").select("*").eq("email", request.email).execute()
    user = response.data[0] if response.data else None

    if user and checkpw(request.password.encode(), user["password_hash"].encode()):
        return {"message": "Login bem-sucedido."}

    raise HTTPException(status_code=401, detail="Credenciais inválidas.")
