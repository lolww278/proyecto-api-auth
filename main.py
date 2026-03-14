from fastapi import FastAPI, HTTPException
from datetime import datetime, timedelta
from jose import jwt, JWTError
import mysql.connector
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from dotenv import load_dotenv
import os

# Cargar variables de entorno desde .env
load_dotenv()

app = FastAPI(title="API de Autenticación")

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Clave secreta desde variable de entorno (nunca hardcodeada)
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Contexto para hashear contraseñas con bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Helpers de base de datos ──────────────────────────────────────────────────

def get_db_connection():
    """Crea una nueva conexión a la BD por cada request."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT", 3306))
    )


# ── Helpers de contraseñas ────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Retorna el hash bcrypt de la contraseña."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica que la contraseña plana coincida con el hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ── Helpers de JWT ────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """Genera un token JWT con expiración."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── Modelos Pydantic ──────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: str
    nombre_c: str
    rol: str
    genero: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/register", status_code=201)
async def register_user(user: UserRegister):
    """Registra un nuevo usuario con contraseña hasheada."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hashed = hash_password(user.password)
        sql = "INSERT INTO usuarios (email, nombre_c, rol, genero, password) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(sql, (user.email, user.nombre_c, user.rol, user.genero, hashed))
        conn.commit()
        return {"message": "Usuario creado correctamente"}
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=409, detail="El email ya está registrado")
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error de base de datos: {err}")
    finally:
        cursor.close()
        conn.close()


@app.post("/login")
async def login(user: UserLogin):
    """Autentica al usuario y retorna un JWT si las credenciales son válidas."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (user.email,))
        db_user = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    # Verificar que el usuario exista y la contraseña sea correcta
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    access_token = create_access_token(
        data={"sub": db_user["email"], "rol": db_user["rol"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/verify_token")
async def verify_token(token: str):
    """Verifica si un JWT es válido y retorna su contenido."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"message": "Token válido", "data": payload}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)