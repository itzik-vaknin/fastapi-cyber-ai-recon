import socket
import ipaddress
import os
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from groq import Groq
import dns.resolver  # הצינור שעוקף את ה-DNS של קאלי!

# ==========================================
# חלק 1: הגדרות ותשתית ה-DATABASE
# ==========================================
DATABASE_URL = "sqlite:///./recon.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanResultModel(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_host = Column(String)
    resolved_ip = Column(String)
    scan_date = Column(String)

Base.metadata.create_all(bind=engine)

# ==========================================
# חלק 2: הקמת השרת ושומר הסף
# ==========================================
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

# ==========================================
# חלק 3: נתיב ההתחברות (LOGIN)
# ==========================================
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username != "admin" or password != "cyber2026":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="שם משתמש או סיסמה שגויים",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": "cyber-recon-secret-key-123", "token_type": "bearer"}

# ==========================================
# חלק 4: הנתיב המוגן - סריקה, שמירה ב-DB וניתוח AI
# ==========================================
@app.get("/api/recon")
def run_recon(target_url: str, token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    
    if token != "cyber-recon-secret-key-123":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    try:
        # בדיקה חכמה: עוקפים את ה-DNS של קאלי ופונים ישירות לשרת חיצוני של קלאודפלייר!
        try:
            ip_obj = ipaddress.ip_address(target_url)
            target_ip = str(ip_obj)
        except ValueError:
            # הגדרת פותר DNS חיצוני (1.1.1.1)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["1.1.1.1"]
            # ניקוי הכתובת מקידומות אם המשתמש הקליד בטעות http://
            clean_url = target_url.replace("https://", "").replace("http://", "").split("/")[0]
            answers = resolver.resolve(clean_url, 'A')
            target_ip = str(answers[0])
        
        # חומת האש נגד SSRF
        ip_check = ipaddress.ip_address(target_ip)
        if ip_check.is_private or ip_check.is_loopback:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDGEN,
                detail="❌ חסימת אבטחה (SSRF): אין אישור לסרוק כתובות IP פנימיות!"
            )
        
        # 2. הרצת סריקת הפורטים המהירה
        ports_to_scan = [21, 22, 80, 443, 8080]
        scan_results = {}
        open_ports_list = []
        
        for port in ports_to_scan:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                scan_results[str(port)] = "open"
                open_ports_list.append(port)
            else:
                scan_results[str(port)] = "closed_or_filtered"
            s.close()
            
        # 3. שמירת הנתונים ב-Database
        new_scan = ScanResultModel(
            target_host=target_url,
            resolved_ip=target_ip,
            scan_date="2026-09-19"
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        
        # 4. הפעלת ה-AI Agent בענן הסילוני של Groq
        if not GROQ_API_KEY:
            ai_analysis = "API Key missing. Please set GROQ_API_KEY environment variable."
        else:
            client = Groq(api_key=GROQ_API_KEY)
            
            ai_prompt = f"""
            You are a cybersecurity expert. Target {target_url} ({target_ip}) was scanned. 
            Open ports: {open_ports_list}. Give a short 1-sentence risk summary in English.
            """
            
            completion = client.chat.completions.create(
                model="openai/gpt-oss-20b",
                messages=[{"role": "user", "content": ai_prompt}]
            )
            ai_analysis = completion.choices[0].message.content.strip()
            
        return {
            "status": "success",
            "saved_in_db_id": new_scan.id,
            "target_host": target_url,
            "resolved_ip": target_ip,
            "port_scan_results": scan_results,
            "ai_analyst_report": ai_analysis
        }
        
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"השרת נתקל בשגיאה הבאה: {str(e)}"
        )

