from flask import Flask, render_template, request, send_file, session, redirect
import os, zipfile, openpyxl, shutil, time, datetime
import bcrypt
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave_super_segura_123")

# =========================
# CONFIG SEGURIDAD
# =========================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=50 * 1024 * 1024
)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# =========================
# HASH
# =========================
def hash_pwd(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt())
def check_pwd(p, h): return bcrypt.checkpw(p.encode(), h)

# =========================
# USUARIOS + ROLES
# =========================
usuarios = {
    "admin": {
        "password": hash_pwd("1234"),
        "rol": "admin"
    },
    "david": {
        "password": hash_pwd("1234"),
        "rol": "usuario"
    }
}

# =========================
# LOGS
# =========================
def log_evento(usuario, accion):
    with open("logs.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - {usuario} - {accion}\n")

# =========================
# RATE LIMIT
# =========================
rate_limit = {}

def check_rate_limit(ip):
    now = time.time()
    if ip not in rate_limit:
        rate_limit[ip] = []

    rate_limit[ip] = [t for t in rate_limit[ip] if now - t < 60]

    if len(rate_limit[ip]) > 20:
        return False

    rate_limit[ip].append(now)
    return True

# =========================
# INTENTOS LOGIN
# =========================
intentos = {}

def ip_cliente():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def permitido(ip):
    data = intentos.get(ip)
    if not data:
        return True
    if data.get("block_until", 0) > time.time():
        return False
    return True

def registrar_fallo(ip):
    data = intentos.setdefault(ip, {"count": 0, "block_until": 0})
    data["count"] += 1
    if data["count"] >= 3:
        data["block_until"] = time.time() + 60

def reset_intentos(ip):
    if ip in intentos:
        intentos[ip] = {"count": 0, "block_until": 0}

# =========================
# HEADERS SEGURIDAD
# =========================
@app.after_request
def secure_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    return resp

# =========================
# NORMALIZAR
# =========================
def normalizar_clave(texto):
    if not texto: return ""
    return str(texto).upper().replace(".ZIP","").replace("_","-").replace(" ","")

# =========================
# EXCEL
# =========================
def cargar_excel(ruta):
    mapeo = {}
    wb = openpyxl.load_workbook(ruta, read_only=True, data_only=True)
    ws = wb.worksheets[0]

    primera = True
    for row in ws.iter_rows(values_only=True):
        if primera:
            primera = False
            continue

        turno = row[1] if len(row) > 1 else None
        expediente = row[13] if len(row) > 13 else None

        if turno and expediente:
            clave = normalizar_clave(expediente)
            mapeo[clave] = str(turno).strip()

    wb.close()
    return mapeo

# =========================
# LOGIN
# =========================
@app.route("/", methods=["GET", "POST"])
def login():
    ip = ip_cliente()

    if not permitido(ip):
        return render_template("login.html", error="Bloqueado temporalmente")

    if request.method == "POST":
        user = request.form["usuario"]
        pwd = request.form["password"]

        if user in usuarios and check_pwd(pwd, usuarios[user]["password"]):
            session["user"] = user
            session["rol"] = usuarios[user]["rol"]
            session.permanent = True
            app.permanent_session_lifetime = 900

            reset_intentos(ip)
            log_evento(user, "Login exitoso")
            return redirect("/app")
        else:
            registrar_fallo(ip)
            return render_template("login.html", error="Credenciales incorrectas")

    return render_template("login.html")

# =========================
# APP
# =========================
@app.route("/app")
def index():
    if "user" not in session:
        return redirect("/")
    return render_template("index.html")

# =========================
# ADMIN
# =========================
@app.route("/admin")
def admin():
    if session.get("rol") != "admin":
        return "Acceso denegado", 403
    return "<h1>Panel Admin</h1><a href='/logs'>Ver logs</a>"

# =========================
# VER LOGS
# =========================
@app.route("/logs")
def ver_logs():
    if session.get("rol") != "admin":
        return "Acceso denegado", 403

    if not os.path.exists("logs.txt"):
        return "Sin logs"

    with open("logs.txt") as f:
        contenido = f.read()

    return f"<pre>{contenido}</pre>"

# =========================
# ZIP SEGURO
# =========================
def safe_extract(zipf, path):
    for member in zipf.namelist():
        p = os.path.abspath(os.path.join(path, member))
        if not p.startswith(os.path.abspath(path)):
            raise Exception("Zip inseguro")
    zipf.extractall(path)

# =========================
# PROCESAR
# =========================
@app.route("/procesar", methods=["POST"])
def procesar():
    if "user" not in session:
        return redirect("/")

    ip = ip_cliente()
    if not check_rate_limit(ip):
        return "Demasiadas solicitudes", 429

    shutil.rmtree(UPLOAD_FOLDER, ignore_errors=True)
    shutil.rmtree(OUTPUT_FOLDER, ignore_errors=True)
    os.makedirs(UPLOAD_FOLDER)
    os.makedirs(OUTPUT_FOLDER)

    excel = request.files.get("excel")
    zips = request.files.getlist("zips")

    excel_path = os.path.join(UPLOAD_FOLDER, secure_filename(excel.filename))
    excel.save(excel_path)

    mapeo = cargar_excel(excel_path)

    procesados = 0

    for z in zips:
        if not z.filename.lower().endswith(".zip"):
            continue

        zip_path = os.path.join(UPLOAD_FOLDER, secure_filename(z.filename))
        z.save(zip_path)

        clave = normalizar_clave(z.filename)

        if clave in mapeo:
            carpeta = os.path.join(OUTPUT_FOLDER, mapeo[clave])
            os.makedirs(carpeta, exist_ok=True)

            try:
                with zipfile.ZipFile(zip_path) as zip_ref:
                    safe_extract(zip_ref, carpeta)
                procesados += 1
            except Exception as e:
                print("Error:", e)

    log_evento(session["user"], f"Procesó {procesados} ZIPs")

    shutil.make_archive("resultado", 'zip', OUTPUT_FOLDER)
    return send_file("resultado.zip", as_attachment=True)

# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)