from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from security_password import hash_password, verify_password
from security_jwt import create_access_token, decode_token

app = FastAPI()

class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

bearer = HTTPBearer()

fake_users_db: dict[str, dict] = {}

def init_sample_users():
    fake_users_db["dr_house"] = {
        "username": "dr_house",
        "hashed_password": hash_password("house123"),
        "role": "doctor"
    }
    fake_users_db["pharma_anna"] = {
        "username": "pharma_anna",
        "hashed_password": hash_password("anna456"),
        "role": "pharmacist"
    }

init_sample_users()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không hợp lệ hoặc đã hết hạn")
    username = payload.get("sub")
    role = payload.get("role")
    if not username or not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không hợp lệ")
    user = fake_users_db.get(username)
    if not user or user.get("role") != role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không hợp lệ")
    return user

@app.post("/api/v1/medical/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    username = data.username.strip()
    password = data.password
    role = data.role.strip().lower()
    if role not in ("doctor", "pharmacist"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role phải là 'doctor' hoặc 'pharmacist'")
    if username in fake_users_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username đã tồn tại")
    hashed = hash_password(password)
    fake_users_db[username] = {"username": username, "hashed_password": hashed, "role": role}
    return {"message": "Đăng ký nhân viên y tế thành công"}

@app.post("/api/v1/medical/login", response_model=TokenResponse)
def login(data: LoginRequest):
    username = data.username.strip()
    password = data.password
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Thông tin đăng nhập không chính xác")
    token = create_access_token(username=user["username"], role=user["role"])
    return TokenResponse(access_token=token)

@app.post("/api/v1/prescriptions")
def create_prescription(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "doctor":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Không đủ quyền hạn để ký đơn thuốc")
    return {"message": f"Bác sĩ {current_user['username']} đã tạo đơn thuốc thành công"}

@app.get("/api/v1/prescriptions/view")
def view_prescriptions(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ("doctor", "pharmacist"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Không đủ quyền hạn")
    return {"message": f"{current_user['role']} {current_user['username']} đang xem danh sách đơn thuốc"}
