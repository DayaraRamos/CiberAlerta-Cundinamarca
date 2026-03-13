from flask import Flask, render_template, request, jsonify
import re
import requests

# ============================================================
#   CIBERALERTA CUNDINAMARCA - Servidor Flask
#   Con integracion de VirusTotal API
#   Proyecto de finalizacion - Bootcamp Ciberseguridad
# ============================================================

from flask import Flask, render_template, request, jsonify, send_from_directory
import os

app = Flask(__name__)

@app.route('/Estilos/<path:filename>')
def estilos(filename):
    return send_from_directory('Estilos', filename)

@app.route('/Funcion/<path:filename>')
def funcion(filename):
    return send_from_directory('Funcion', filename)

# ---------- CONFIGURACION VIRUSTOTAL ----------
# Aqui si o si toca reemplazar esto con la API Key de virustotal.com
VIRUSTOTAL_API_KEY = "68df8dff822c44acae54425699f03f72754ff07a03ff3d668333108395a06795"
VIRUSTOTAL_URL_SCAN  = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_FILE_SCAN = "https://www.virustotal.com/api/v3/files"

# ---------- BASE DE CONOCIMIENTO ----------
PALABRAS_PELIGROSAS = [
    "ganaste", "gano", "premio", "felicitaciones has sido seleccionado",
    "urgente", "inmediatamente", "cuenta bloqueada", "cuenta suspendida",
    "verificar cuenta", "haz clic", "clic aqui",
    "confirma tus datos", "ingresa tus datos", "actualiza tus datos",
    "transferencia pendiente", "pago pendiente",
    "vas a perder", "perderas", "ultima oportunidad",
    "gratis", "regalo", "bono", "whatsapp gold", "whatsapp plus",
    "gobierno te da", "subsidio disponible", "beneficiario",
    "ingresa aqui", "entra aqui", "contrasena", "clave", "pin",
]

ACORTADORES = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.io", "cutt.ly", "rebrand.ly", "tiny.cc",
]

PATRONES_DOMINIOS_FALSOS = [
    r"bancol0mbia", r"bancolombia\d+", r"nequi-",
    r"gov\.co\.", r"dian-", r"g00gle", r"faceb00k",
]


# ---------- FUNCION VIRUSTOTAL ----------
def verificar_url_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(VIRUSTOTAL_URL_SCAN, headers=headers, data=f"url={url}", timeout=10)
        if response.status_code != 200:
            return {"error": "No se pudo conectar con VirusTotal"}
        analisis_id = response.json()["data"]["id"]
        resultado = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analisis_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        stats = resultado.json()["data"]["attributes"]["stats"]
        maliciosos = stats.get("malicious", 0)
        sospechosos = stats.get("suspicious", 0)
        total = sum(stats.values())
        veredicto = "peligroso" if maliciosos >= 3 else "sospechoso" if maliciosos >= 1 or sospechosos >= 2 else "limpio"
        return {"total": total, "maliciosos": maliciosos, "sospechosos": sospechosos, "veredicto": veredicto, "url": url}
    except Exception as e:
        return {"error": f"Error al consultar VirusTotal: {str(e)}"}

def verificar_archivo_virustotal(archivo_bytes, nombre_archivo):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        files = {"file": (nombre_archivo, archivo_bytes)}
        response = requests.post(VIRUSTOTAL_FILE_SCAN, headers=headers, files=files, timeout=30)
        if response.status_code != 200:
            return {"error": f"Error al subir el archivo (codigo {response.status_code})"}
        analisis_id = response.json()["data"]["id"]
        resultado = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analisis_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=30)
        stats = resultado.json()["data"]["attributes"]["stats"]
        maliciosos = stats.get("malicious", 0)
        sospechosos = stats.get("suspicious", 0)
        total = sum(stats.values())
        veredicto = "peligroso" if maliciosos >= 3 else "sospechoso" if maliciosos >= 1 or sospechosos >= 2 else "limpio"
        return {"total": total, "maliciosos": maliciosos, "sospechosos": sospechosos, "veredicto": veredicto, "nombre": nombre_archivo}
    except Exception as e:
        return {"error": f"Error al analizar archivo: {str(e)}"}

# ---------- LOGICA DE ANALISIS ----------
def analizar_mensaje(texto):
    texto_lower = texto.lower()
    razones = []
    puntaje = 0
    resultado_vt = None

    palabras_encontradas = [p for p in PALABRAS_PELIGROSAS if p in texto_lower]
    palabras_sin_bancos = [p for p in palabras_encontradas if p not in ["nequi","daviplata","bancolombia"]]
    if len(palabras_sin_bancos) >= 3:
        puntaje += 3
        razones.append(f"Contiene {len(palabras_sin_bancos)} frases tipicas de estafa: '{palabras_sin_bancos[0]}', '{palabras_sin_bancos[1]}'...")
    elif len(palabras_sin_bancos) >= 1:
        puntaje += 1
        razones.append(f"Contiene frases sospechosas: '{palabras_sin_bancos[0]}'")

    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+|bit\.ly[^\s]*', texto_lower)
    for url in urls:
        for acortador in ACORTADORES:
            if acortador in url:
                puntaje += 2
                razones.append(f"Contiene enlace acortado ({acortador}). Los estafadores lo usan para ocultar el destino real.")
                break
        for patron in PATRONES_DOMINIOS_FALSOS:
            if re.search(patron, url):
                puntaje += 4
                razones.append("El enlace imita a una entidad conocida pero es FALSO.")
                break
        if url.startswith("http://"):
            puntaje += 1
            razones.append("El enlace NO es seguro (no tiene https).")
        if VIRUSTOTAL_API_KEY != "TU_API_KEY_AQUI":
            vt = verificar_url_virustotal(url)
            if "error" not in vt:
                resultado_vt = vt
                if vt["veredicto"] == "peligroso":
                    puntaje += 5
                    razones.append(f"VirusTotal: {vt['maliciosos']} de {vt['total']} antivirus detectaron este enlace como MALICIOSO.")
                elif vt["veredicto"] == "sospechoso":
                    puntaje += 2
                    razones.append(f"VirusTotal: El enlace es sospechoso segun {vt['sospechosos']} antivirus.")
                else:
                    razones.append(f"VirusTotal: Enlace analizado por {vt['total']} antivirus y parece limpio.")

    for u in ["ahora mismo","hoy vence","expira hoy","ultimo dia","caduca","caduque"]:
        if u in texto_lower:
            puntaje += 2
            razones.append(f"Crea urgencia falsa con '{u}'. Los estafadores presionan para que no pienses.")
            break
    for dato in ["cedula","numero de cuenta","datos bancarios","clave","contrasena","pin"]:
        if dato in texto_lower:
            puntaje += 3
            razones.append(f"Pide informacion personal ('{dato}'). Ninguna entidad legitima pide esto por mensaje.")
            break
    for p in ["millones","miles de pesos","iphone","televisor","carro","moto"]:
        if p in texto_lower:
            puntaje += 2
            razones.append(f"Promete premios o dinero ('{p}'). Si suena demasiado bueno, es una estafa.")
            break

    if puntaje == 0 and not razones:
        nivel = "seguro"
        razones = ["No se encontraron senales de peligro en este mensaje."]
    elif puntaje <= 2:
        nivel = "sospechoso"
    else:
        nivel = "peligroso"

    consejos_base = ["Nunca compartas tu clave, PIN o contrasena con nadie.","Las entidades oficiales NUNCA piden datos por WhatsApp.","Antes de hacer clic, preguntale a alguien de confianza.","Si recibes un mensaje del banco, llama directamente."]
    if nivel == "peligroso":
        consejos = ["NO respondas este mensaje.","NO hagas clic en ningun enlace.","NO compartas este mensaje.","Bloquea y reporta al remitente.","Si ya hiciste clic, cambia tus contrasenas."] + consejos_base
    elif nivel == "sospechoso":
        consejos = ["No respondas todavia.","Verifica por otro medio oficial.","Si es del banco, llama al numero del reverso de tu tarjeta.","Consulta con un familiar antes de actuar."] + consejos_base
    else:
        consejos = ["El mensaje parece seguro.","Igual, nunca compartas informacion personal.","Manten actualizadas tus contrasenas."]

    return {"nivel": nivel, "razones": razones, "consejos": consejos, "virustotal": resultado_vt}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analizar", methods=["POST"])
def analizar():
    datos = request.get_json()
    texto = datos.get("texto", "")
    if not texto or len(texto) < 10:
        return jsonify({"error": "Mensaje muy corto"}), 400
    return jsonify(analizar_mensaje(texto))

@app.route("/analizar-archivo", methods=["POST"])
def analizar_archivo():
    if "archivo" not in request.files:
        return jsonify({"error": "No se recibio ningun archivo"}), 400
    archivo = request.files["archivo"]
    if archivo.filename == "":
        return jsonify({"error": "Nombre de archivo vacio"}), 400
    archivo_bytes = archivo.read()
    if VIRUSTOTAL_API_KEY == "TU_API_KEY_AQUI":
        return jsonify({"error": "Configura tu API Key de VirusTotal en app.py"}), 400
    resultado_vt = verificar_archivo_virustotal(archivo_bytes, archivo.filename)
    return jsonify({"virustotal": resultado_vt})

if __name__ == "__main__":
    import webbrowser
    webbrowser.open("http://localhost:5000")
    app.run(debug=False)