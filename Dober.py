from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from pydantic import BaseModel
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
import os

# 📦 Carregar variáveis de ambiente do .env
load_dotenv()

SUPABASE_URL: str | None = os.getenv("SUPABASE_URL")
SUPABASE_KEY: str | None = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("As variáveis SUPABASE_URL e SUPABASE_KEY são obrigatórias no .env.")

# 🔗 Criar cliente Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Cliente Supabase criado com sucesso.")

# 🚀 Inicializar API FastAPI
app = FastAPI()

# 🔓 CORS liberado (pode ajustar para domínios específicos depois)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 📄 Modelos de entrada de dados
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# 🔐 Rota de registro
@app.post("/register")
def register(request: RegisterRequest):
    # Verifica se o e-mail já existe
    response = supabase.table("users").select("email").eq("email", request.email).execute()
    if response.data:
        raise HTTPException(status_code=400, detail="Usuário já registrado.")

    # Criptografa senha
    hashed_password = hashpw(request.password.encode(), gensalt()).decode()

    # Insere novo usuário
    supabase.table("users").insert({
        "username": request.username,
        "email": request.email,
        "password_hash": hashed_password
    }).execute()

    return {"message": "Usuário registrado com sucesso."}

# 🔓 Rota de login
@app.post("/login")
def login(request: LoginRequest):
    response = supabase.table("users").select("*").eq("email", request.email).execute()
    user = response.data[0] if response.data else None

    if user and checkpw(request.password.encode(), user["password_hash"].encode()):
        return {"message": "Login bem-sucedido."}

    raise HTTPException(status_code=401, detail="Credenciais inválidas.")
