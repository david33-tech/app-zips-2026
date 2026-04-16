from flask import Flask, render_template, request, send_file, session, redirect
import os
import zipfile
import openpyxl
import shutil

app = Flask(__name__)
app.secret_key = "clave_super_segura_123"

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# =========================
# USUARIOS
# =========================
usuarios = {
    "admin": "1234",
    "david": "1234"
}

# =========================
# NORMALIZAR CLAVE
# =========================
def normalizar_clave(texto):
    if not texto:
        return ""

    t = str(texto).upper()
    t = t.replace(".ZIP", "")
    t = t.replace("_", "-")
    t = t.replace(" ", "")

    return t

# =========================
# LEER EXCEL (2026)
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

        turno = row[1] if len(row) > 1 else None      # B
        expediente = row[13] if len(row) > 13 else None  # N

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

    if request.method == "POST":
        user = request.form["usuario"]
        pwd = request.form["password"]

        if user in usuarios and usuarios[user] == pwd:
            session["user"] = user
            return redirect("/app")
        else:
            return render_template("login.html", error="Credenciales incorrectas")

    return render_template("login.html")

# =========================
# APP PROTEGIDA
# =========================
@app.route("/app")
def index():

    if "user" not in session:
        return redirect("/")

    return render_template("index.html")

# =========================
# PROCESAR
# =========================
@app.route("/procesar", methods=["POST"])
def procesar():

    if "user" not in session:
        return redirect("/")

    shutil.rmtree(UPLOAD_FOLDER, ignore_errors=True)
    shutil.rmtree(OUTPUT_FOLDER, ignore_errors=True)

    os.makedirs(UPLOAD_FOLDER)
    os.makedirs(OUTPUT_FOLDER)

    excel = request.files["excel"]
    zips = request.files.getlist("zips")

    excel_path = os.path.join(UPLOAD_FOLDER, excel.filename)
    excel.save(excel_path)

    mapeo = cargar_excel(excel_path)

    for z in zips:
        zip_path = os.path.join(UPLOAD_FOLDER, z.filename)
        z.save(zip_path)

        clave = normalizar_clave(z.filename)

        if clave in mapeo:
            carpeta = os.path.join(OUTPUT_FOLDER, mapeo[clave])
            os.makedirs(carpeta, exist_ok=True)

            try:
                with zipfile.ZipFile(zip_path) as zip_ref:
                    zip_ref.extractall(carpeta)
            except Exception as e:
                print(f"Error con {z.filename}: {e}")

    shutil.make_archive("resultado", 'zip', OUTPUT_FOLDER)

    return send_file("resultado.zip", as_attachment=True)

# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# =========================
if __name__ == "__main__":
    app.run(debug=True)