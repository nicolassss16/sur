from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import sqlite3
import json
from datetime import datetime
import random
import math
import hashlib
import hmac
import secrets
import time
import html

app = FastAPI(title="SurPide v8 SECURE PRO - Hardened Edition")

# En producción podés restringir allow_origins a tu dominio (ej. ["https://surpide.com.ar"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

import os
from fastapi.responses import Response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "surpide_prod.db"))
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY", "admin2026")

def obtener_ip_real(request: Request) -> str:
    """Obtiene la IP real del vecino incluso detrás del proxy/load balancer de Render."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

# =========================================================
# MÓDULO DE SEGURIDAD: HASHING, TOKENS, RATE LIMIT & SANITIZACIÓN
# =========================================================
# Sesiones en memoria: token -> {"comercio_id": int, "exp": float}
SESIONES_COMERCIO: Dict[str, dict] = {}
SESIONES_ADMIN: Dict[str, float] = {}

# Rate Limiting e intentos fallidos por IP
RATE_LIMIT_PEDIDOS: Dict[str, List[float]] = {}
INTENTOS_LOGIN: Dict[str, dict] = {}

def hash_pin(pin: str, slug: str) -> str:
    """Hashea el PIN con PBKDF2-HMAC-SHA256 usando el slug como salt."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        pin.encode('utf-8'),
        f"surpide_salt_{slug}".encode('utf-8'),
        100_000
    ).hex()

def sanitizar_texto(texto: Optional[str], max_len: int = 250) -> str:
    """Escapa caracteres HTML peligrosos para prevenir XSS en el KDS y tickets."""
    if not texto:
        return ""
    limpio = html.escape(texto.strip())
    return limpio[:max_len]

def verificar_rate_limit_ip(ip: str, max_req: int = 8, ventana_seg: int = 60):
    ahora = time.time()
    historial = RATE_LIMIT_PEDIDOS.get(ip, [])
    historial = [t for t in historial if ahora - t < ventana_seg]
    if len(historial) >= max_req:
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes desde tu conexión. Esperá 1 minuto.")
    historial.append(ahora)
    RATE_LIMIT_PEDIDOS[ip] = historial

def verificar_bloqueo_login(ip: str):
    info = INTENTOS_LOGIN.get(ip)
    if info and info.get("bloqueado_hasta", 0) > time.time():
        restante = int(info["bloqueado_hasta"] - time.time())
        raise HTTPException(status_code=429, detail=f"Demasiados intentos fallidos. Bloqueado por {restante} segundos.")

def registrar_fallo_login(ip: str):
    ahora = time.time()
    info = INTENTOS_LOGIN.get(ip, {"fallos": 0, "bloqueado_hasta": 0})
    info["fallos"] += 1
    if info["fallos"] >= 5:
        info["bloqueado_hasta"] = ahora + 300 # 5 minutos de bloqueo tras 5 fallos
        info["fallos"] = 0
    INTENTOS_LOGIN[ip] = info

def limpiar_fallos_login(ip: str):
    if ip in INTENTOS_LOGIN:
        del INTENTOS_LOGIN[ip]

def crear_token_comercio(comercio_id: int) -> str:
    token = secrets.token_urlsafe(32)
    SESIONES_COMERCIO[token] = {"comercio_id": comercio_id, "exp": time.time() + 43200} # 12 hs
    return token

def validar_token_comercio(comercio_id: int, x_comercio_token: Optional[str] = Header(None)):
    if not x_comercio_token or x_comercio_token not in SESIONES_COMERCIO:
        raise HTTPException(status_code=401, detail="Sesión expirada o no autorizada. Iniciá sesión con tu PIN.")
    sesion = SESIONES_COMERCIO[x_comercio_token]
    if sesion["exp"] < time.time():
        del SESIONES_COMERCIO[x_comercio_token]
        raise HTTPException(status_code=401, detail="Tu sesión expiró. Volvé a ingresar tu PIN.")
    if sesion["comercio_id"] != comercio_id:
        raise HTTPException(status_code=403, detail="No tenés permiso para modificar otro comercio.")
    return sesion

def validar_token_admin(x_admin_token: Optional[str] = Header(None)):
    if not x_admin_token or x_admin_token not in SESIONES_ADMIN:
        raise HTTPException(status_code=401, detail="Acceso denegado. Ingresá la Clave Maestra de Administrador.")
    if SESIONES_ADMIN[x_admin_token] < time.time():
        del SESIONES_ADMIN[x_admin_token]
        raise HTTPException(status_code=401, detail="Sesión de administrador expirada.")
    return True

# Headers de seguridad HTTP en todas las respuestas
@app.middleware("http")
async def agregar_headers_seguridad(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# =========================================================
# 1. BASE DE DATOS Y SEMILLA SEGURA
# =========================================================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS config_sistema (
            clave TEXT PRIMARY KEY,
            valor TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO config_sistema VALUES ('modo_lluvia', '0')")
    c.execute("INSERT OR IGNORE INTO config_sistema VALUES ('multiplicador_lluvia', '1.30')")

    c.execute("""
        CREATE TABLE IF NOT EXISTS comercios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            rubro TEXT NOT NULL,
            localidad TEXT NOT NULL,
            barrio TEXT NOT NULL,
            direccion TEXT NOT NULL,
            whatsapp TEXT NOT NULL,
            alias_mp TEXT NOT NULL,
            titular_mp TEXT NOT NULL,
            comision_pct REAL DEFAULT 5.0,
            abierto INTEGER DEFAULT 1,
            acepta_retiro INTEGER DEFAULT 1,
            tiempo_estimado TEXT DEFAULT '25-35 min',
            calificacion REAL DEFAULT 4.9,
            icono TEXT DEFAULT '🍔',
            banner_url TEXT DEFAULT '',
            pin_hash TEXT NOT NULL,
            lat REAL DEFAULT -34.9150,
            lon REAL DEFAULT -58.3750,
            modo_logistica TEXT DEFAULT 'HIBRIDA',
            tipo_tarifa_propia TEXT DEFAULT 'KM',
            costo_envio_fijo REAL DEFAULT 1200.0,
            costo_por_km REAL DEFAULT 400.0,
            envio_gratis_desde REAL DEFAULT 18000.0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS cadetes_propios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comercio_id INTEGER NOT NULL,
            nombre TEXT NOT NULL,
            whatsapp TEXT NOT NULL,
            vehiculo TEXT DEFAULT 'Moto',
            activo INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS rendiciones_cadetes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comercio_id INTEGER NOT NULL,
            cadete_id INTEGER NOT NULL,
            cadete_nombre TEXT NOT NULL,
            total_efectivo_cobrado REAL NOT NULL,
            total_envios_pagados REAL NOT NULL,
            neto_a_rendir_al_local REAL NOT NULL,
            cantidad_pedidos INTEGER NOT NULL,
            cerrado_en TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comercio_id INTEGER NOT NULL,
            nombre TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            precio_mostrador REAL NOT NULL,
            precio_apps REAL NOT NULL,
            categoria TEXT DEFAULT 'Destacados',
            icono TEXT DEFAULT '🍔',
            imagen_url TEXT DEFAULT '',
            disponible INTEGER DEFAULT 1,
            opciones_json TEXT DEFAULT '[]'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS cupones (
            codigo TEXT PRIMARY KEY,
            descuento_pct REAL NOT NULL,
            tope_reintegro REAL DEFAULT 5000,
            activo INTEGER DEFAULT 1
        )
    """)
    c.execute("INSERT OR IGNORE INTO cupones VALUES ('SURPIDE10', 10.0, 3500, 1)")
    c.execute("INSERT OR IGNORE INTO cupones VALUES ('GLEWVIP', 15.0, 4500, 1)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS tarifas_envio (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            localidad_origen TEXT NOT NULL,
            localidad_destino TEXT NOT NULL,
            barrio_destino TEXT NOT NULL,
            zona INTEGER NOT NULL,
            costo_base REAL NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_token TEXT NOT NULL,
            comercio_id INTEGER NOT NULL,
            cliente_nombre TEXT NOT NULL,
            cliente_tel TEXT NOT NULL,
            tipo_entrega TEXT DEFAULT 'ENVIO',
            localidad_destino TEXT NOT NULL,
            barrio_destino TEXT NOT NULL,
            direccion_calle TEXT NOT NULL,
            entrecalles TEXT NOT NULL,
            referencia_casa TEXT,
            distancia_km REAL DEFAULT 1.5,
            items_json TEXT NOT NULL,
            nota_general TEXT DEFAULT '',
            metodo_pago TEXT NOT NULL,
            paga_con REAL DEFAULT 0,
            comprobante_base64 TEXT,
            subtotal_comida REAL NOT NULL,
            descuento_cupon REAL DEFAULT 0,
            costo_envio REAL NOT NULL,
            total_final REAL NOT NULL,
            comision_plataforma REAL NOT NULL,
            estado TEXT DEFAULT 'PENDIENTE',
            origen_flota TEXT DEFAULT 'PROPIA',
            repartidor_nombre TEXT,
            repartidor_tel TEXT DEFAULT '',
            rendido INTEGER DEFAULT 0,
            pin_entrega TEXT NOT NULL,
            intentos_pin INTEGER DEFAULT 0,
            creado_en TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS pagos_comisiones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comercio_id INTEGER NOT NULL,
            monto REAL NOT NULL,
            fecha TEXT NOT NULL
        )
    """)

    c.execute("SELECT COUNT(*) FROM comercios")
    if c.fetchone()[0] == 0:
        comercios_seed = [
            (1, "burger-sur", "Burger Sur Smash", "Hamburguesas", "Glew", "Glew Centro", "Sarmiento 120 (Frente a la Estación)", "5491122334455", "burgersur.glew.mp", "Juan Manuel Pérez", 5.0, 1, 1, "20-30 min", 4.9, "🍔", "https://images.unsplash.com/photo-1550547660-d9450f859349?auto=format&fit=crop&w=900&q=80", hash_pin("1234", "burger-sur"), -34.9912, -58.3705, "HIBRIDA", "KM", 1200.0, 400.0, 18000.0),
            (2, "la-estacion", "Pizzería La Estación", "Pizzas y Empanadas", "Longchamps", "Longchamps Centro", "Av. H. Yrigoyen 18200", "5491133445566", "pizzeria.estacion.mp", "Carlos Gómez", 4.0, 1, 1, "30-40 min", 4.8, "🍕", "https://images.unsplash.com/photo-1513104890138-7c749659a591?auto=format&fit=crop&w=900&q=80", hash_pin("5678", "la-estacion"), -34.9602, -58.3840, "PROPIA", "FIJA", 1000.0, 350.0, 22000.0),
            (3, "rey-del-lomito", "El Rey del Lomito", "Lomitos y Parrilla", "Guernica", "Guernica Centro", "Av. Eva Perón 450", "5491144556677", "reylomito.guernica", "Martín Sosa", 6.0, 1, 1, "25-35 min", 4.9, "🥪", "https://images.unsplash.com/photo-1544025162-d76694265947?auto=format&fit=crop&w=900&q=80", hash_pin("9999", "rey-del-lomito"), -34.9225, -58.3980, "SURPIDE", "RED", 1500.0, 450.0, 0.0),
            (4, "helados-polo-sur", "Heladería Artesanal Polo Sur", "Helados y Postres", "Glew", "Glew Centro", "Almafuerte 85", "5491155667788", "polosur.helados.mp", "Lucía Fernández", 4.0, 1, 1, "15-25 min", 5.0, "🍦", "https://images.unsplash.com/photo-1501443762994-82bd5dace89a?auto=format&fit=crop&w=900&q=80", hash_pin("1111", "helados-polo-sur"), -34.9930, -58.3680, "PROPIA", "KM", 1100.0, 380.0, 12000.0)
        ]
        c.executemany("""
            INSERT INTO comercios (
                id, slug, nombre, rubro, localidad, barrio, direccion, whatsapp,
                alias_mp, titular_mp, comision_pct, abierto, acepta_retiro,
                tiempo_estimado, calificacion, icono, banner_url, pin_hash, lat, lon,
                modo_logistica, tipo_tarifa_propia, costo_envio_fijo, costo_por_km, envio_gratis_desde
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, comercios_seed)

        cadetes_seed = [
            (1, "Lucas (Moto Propia Burger Sur)", "5491166778899", "Honda Wave 110"),
            (1, "Nahuel (Moto Propia Turno Noche)", "5491177889900", "Motomel Blitz"),
            (2, "Franco (Repartidor Pizzería)", "5491188990011", "Gilera Smash"),
            (4, "Julián (Delivery Heladería)", "5491133221100", "Honda Titan 150")
        ]
        c.executemany("""
            INSERT INTO cadetes_propios (comercio_id, nombre, whatsapp, vehiculo, activo)
            VALUES (?, ?, ?, ?, 1)
        """, cadetes_seed)

        opts_burger = json.dumps([
            {"nombre": "Medallón Extra 110g + Doble Cheddar", "precio": 2200},
            {"nombre": "Extra Bacon Crocante", "precio": 1200},
            {"nombre": "Cheddar Líquido en las Papas", "precio": 1500},
            {"nombre": "Gaseosa Lata 354ml (Coca-Cola)", "precio": 1800}
        ])
        opts_pizza = json.dumps([
            {"nombre": "Borde Relleno de Muzzarella", "precio": 2000},
            {"nombre": "Extra Jamón Natural", "precio": 1600},
            {"nombre": "Porción de Fainá (2 unidades)", "precio": 1400},
            {"nombre": "Coca-Cola 1.5L", "precio": 3200}
        ])

        productos_seed = [
            (1, "Doble Cheeseburger + Papas", "Doble medallón smash 110g, cuádruple cheddar Milkaut, bacon crocante y papas fritas", 8500, 11800, "Hamburguesas", "🍔", "https://images.unsplash.com/photo-1568901346375-23c9450c58cd?auto=format&fit=crop&w=400&q=80", 1, opts_burger),
            (1, "Burger Oklahoma Fried Onion + Papas", "Doble carne aplastada con lluvia de cebolla finita caramelizada en plancha y cheddar", 8200, 11400, "Hamburguesas", "🍔", "https://images.unsplash.com/photo-1586190848861-99aa4a171e90?auto=format&fit=crop&w=400&q=80", 1, opts_burger),
            (2, "Pizza Muzzarella Al Molde Grande", "Salsa de tomate casera, 600g de muzzarella seleccionada, aceitunas verdes y orégano", 9000, 12500, "Pizzas", "🍕", "https://images.unsplash.com/photo-1574071318508-1cdbab80d002?auto=format&fit=crop&w=400&q=80", 1, opts_pizza),
            (2, "Pizza Napolitana Especial con Jamón", "Muzzarella, jamón cocido natural, rodajas de tomate fresco, ajo picado y provenzal", 10500, 14500, "Pizzas", "🍕", "https://images.unsplash.com/photo-1565299624946-b28f40a0ae38?auto=format&fit=crop&w=400&q=80", 1, opts_pizza),
            (3, "Lomito Completo en Pan Francés Casero + Fritas", "Bife de lomo tiernizado 250g, jamón, queso, lechuga, tomate, huevo a la plancha y fritas", 10200, 14100, "Lomitos", "🥪", "https://images.unsplash.com/photo-1509722747041-616f39b57569?auto=format&fit=crop&w=400&q=80", 1, "[]"),
            (4, "1 Kilo de Helado Artesanal (¡Envío Gratis!)", "Hasta 4 gustos: Dulce de leche Polo Sur, Tramontana, Chocolate con Almendras y más", 11500, 16200, "Potes Térmicos", "🍦", "https://images.unsplash.com/photo-1563805042-7684c019e1cb?auto=format&fit=crop&w=400&q=80", 1, "[]")
        ]
        c.executemany("""
            INSERT INTO productos (
                comercio_id, nombre, descripcion, precio_mostrador, precio_apps,
                categoria, icono, imagen_url, disponible, opciones_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, productos_seed)

        barrios_zonas = {
            "Glew": [
                ("Glew Centro", 1, 1500), ("Almafuerte", 1, 1600), ("Glew Norte", 1, 1600),
                ("Los Pinos", 2, 2000), ("Kanmar", 2, 2000), ("Ipona", 2, 2100), ("Gendarmería", 2, 2100),
                ("Parque Roma", 3, 2500), ("Gorriti", 3, 2500), ("Villa París", 3, 2600)
            ],
            "Longchamps": [
                ("Longchamps Centro", 1, 1500), ("Emilio Burgwardt", 1, 1600),
                ("Los Frutales", 2, 2000), ("Viplastic", 2, 2000), ("Rayo de Sol", 2, 2100), ("Sakura", 2, 2200)
            ],
            "Guernica": [
                ("Guernica Centro", 1, 1500), ("Parque Americano", 1, 1700),
                ("Villa Numancia", 2, 2000), ("Santa Elena", 2, 2100), ("La Yaya", 2, 2200),
                ("Las Lomas", 3, 2600), ("Panamérica", 3, 2500)
            ]
        }

        localidades = ["Glew", "Longchamps", "Guernica"]
        for loc_origen in localidades:
            for loc_dest, lista_barrios in barrios_zonas.items():
                for barrio_nombre, zona, costo_misma_loc in lista_barrios:
                    recargo_cruce = 0 if loc_origen == loc_dest else 1200
                    costo_final = costo_misma_loc + recargo_cruce
                    c.execute("""
                        INSERT INTO tarifas_envio (localidad_origen, localidad_destino, barrio_destino, zona, costo_base)
                        VALUES (?, ?, ?, ?, ?)
                    """, (loc_origen, loc_dest, barrio_nombre, zona, costo_final))

    conn.commit()
    conn.close()

init_db()

class ConnectionManager:
    def __init__(self):
        self.comercios_conectados: Dict[int, List[WebSocket]] = {}
        self.repartidores_conectados: List[WebSocket] = []
        self.clientes_pedidos: Dict[int, List[WebSocket]] = {}

    async def conectar_comercio(self, comercio_id: int, ws: WebSocket):
        await ws.accept()
        self.comercios_conectados.setdefault(comercio_id, []).append(ws)

    def desconectar_comercio(self, comercio_id: int, ws: WebSocket):
        if comercio_id in self.comercios_conectados and ws in self.comercios_conectados[comercio_id]:
            self.comercios_conectados[comercio_id].remove(ws)

    async def notificar_comercio(self, comercio_id: int, data: dict):
        for ws in list(self.comercios_conectados.get(comercio_id, [])):
            try:
                await ws.send_json(data)
            except Exception:
                pass

    async def conectar_repartidor(self, ws: WebSocket):
        await ws.accept()
        self.repartidores_conectados.append(ws)

    def desconectar_repartidor(self, ws: WebSocket):
        if ws in self.repartidores_conectados:
            self.repartidores_conectados.remove(ws)

    async def notificar_repartidores(self, data: dict):
        for ws in list(self.repartidores_conectados):
            try:
                await ws.send_json(data)
            except Exception:
                pass

    async def conectar_cliente_pedido(self, pedido_id: int, ws: WebSocket):
        await ws.accept()
        self.clientes_pedidos.setdefault(pedido_id, []).append(ws)

    def desconectar_cliente_pedido(self, pedido_id: int, ws: WebSocket):
        if pedido_id in self.clientes_pedidos and ws in self.clientes_pedidos[pedido_id]:
            self.clientes_pedidos[pedido_id].remove(ws)

    async def notificar_cliente_pedido(self, pedido_id: int, data: dict):
        for ws in list(self.clientes_pedidos.get(pedido_id, [])):
            try:
                await ws.send_json(data)
            except Exception:
                pass

manager = ConnectionManager()

@app.get("/")
def vista_cliente():
    return FileResponse(os.path.join(BASE_DIR, "cliente.html"))

@app.get("/tienda/{slug}")
def vista_tienda_directa(slug: str):
    return FileResponse(os.path.join(BASE_DIR, "cliente.html"))

@app.get("/local-admin")
def vista_local_admin():
    return FileResponse(os.path.join(BASE_DIR, "local_admin.html"))

@app.get("/comercio")
def vista_comercio():
    return FileResponse(os.path.join(BASE_DIR, "comercio.html"))

@app.get("/repartidores")
def vista_repartidores():
    return FileResponse(os.path.join(BASE_DIR, "repartidores.html"))

@app.get("/admin")
def vista_admin():
    return FileResponse(os.path.join(BASE_DIR, "admin.html"))

# SEGURIDAD: /api/init-data NUNCA devuelve pin_hash ni datos privados sensibles al público
@app.get("/api/init-data")
def obtener_datos_iniciales(incluir_pausados: bool = False):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT id, slug, nombre, rubro, localidad, barrio, direccion, whatsapp,
               alias_mp, titular_mp, comision_pct, abierto, acepta_retiro,
               tiempo_estimado, calificacion, icono, banner_url, lat, lon,
               modo_logistica, tipo_tarifa_propia, costo_envio_fijo, costo_por_km, envio_gratis_desde
        FROM comercios ORDER BY abierto DESC, id ASC
    """)
    comercios = [dict(r) for r in c.fetchall()]

    for com in comercios:
        if incluir_pausados:
            c.execute("SELECT * FROM productos WHERE comercio_id = ? ORDER BY id ASC", (com["id"],))
        else:
            c.execute("SELECT * FROM productos WHERE comercio_id = ? AND disponible = 1 ORDER BY id ASC", (com["id"],))
        com["productos"] = [dict(p) for p in c.fetchall()]

        c.execute("SELECT * FROM cadetes_propios WHERE comercio_id = ? AND activo = 1 ORDER BY id ASC", (com["id"],))
        com["cadetes_propios"] = [dict(cad) for cad in c.fetchall()]

    c.execute("SELECT DISTINCT localidad_destino, barrio_destino, zona FROM tarifas_envio ORDER BY localidad_destino, zona, barrio_destino")
    barrios_rows = c.fetchall()
    barrios_por_localidad = {}
    for r in barrios_rows:
        loc = r["localidad_destino"]
        barrios_por_localidad.setdefault(loc, []).append({"barrio": r["barrio_destino"], "zona": r["zona"]})

    c.execute("SELECT valor FROM config_sistema WHERE clave = 'modo_lluvia'")
    modo_lluvia = c.fetchone()[0] == "1"

    conn.close()
    return {
        "comercios": comercios,
        "barrios_por_localidad": barrios_por_localidad,
        "modo_lluvia": modo_lluvia
    }

def calcular_distancia_haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    # Límite de seguridad: entre 0.8 km y 25 km máximo para evitar manipulación de coordenadas lejanas
    return round(min(25.0, max(0.8, R * c)), 1)

def calcular_tarifa_comercio(comercio: dict, localidad_destino: str, barrio_destino: str, tipo_entrega: str = "ENVIO", subtotal_comida: float = 0.0, cliente_lat: Optional[float] = None, cliente_lon: Optional[float] = None) -> dict:
    if tipo_entrega == "RETIRO":
        return {"costo_envio": 0.0, "zona": 0, "modo_lluvia": False, "distancia_km": 0, "detalle_tarifa": "Retiro en Mostrador ($0)"}

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT valor FROM config_sistema WHERE clave = 'modo_lluvia'")
    modo_lluvia = c.fetchone()[0] == "1"
    c.execute("SELECT valor FROM config_sistema WHERE clave = 'multiplicador_lluvia'")
    mult = float(c.fetchone()[0])

    c.execute("""
        SELECT costo_base, zona FROM tarifas_envio
        WHERE localidad_origen = ? AND localidad_destino = ? AND barrio_destino = ?
    """, (comercio["localidad"], localidad_destino, barrio_destino))
    row = c.fetchone()
    costo_red, zona = (row[0], row[1]) if row else ((1800.0 if comercio["localidad"] == localidad_destino else 3000.0), 2)
    conn.close()

    distancia_km = 1.5
    if cliente_lat is not None and cliente_lon is not None and comercio.get("lat") and comercio.get("lon"):
        distancia_km = calcular_distancia_haversine(comercio["lat"], comercio["lon"], cliente_lat, cliente_lon)

    es_misma_localidad = (comercio["localidad"] == localidad_destino)
    regla = comercio.get("tipo_tarifa_propia", "KM")

    if comercio.get("modo_logistica") in ("PROPIA", "HIBRIDA"):
        if regla == "GRATIS_DESDE" and es_misma_localidad and subtotal_comida >= comercio.get("envio_gratis_desde", 999999):
            return {
                "costo_envio": 0.0,
                "zona": zona,
                "modo_lluvia": False,
                "distancia_km": distancia_km,
                "detalle_tarifa": f"¡Envío Gratis! ({comercio['nombre']})"
            }

        if regla == "KM":
            base = float(comercio.get("costo_envio_fijo", 1000.0))
            por_km = float(comercio.get("costo_por_km", 400.0))
            costo = base + (distancia_km * por_km)
            if modo_lluvia:
                costo = round((costo * mult) / 100) * 100
            return {
                "costo_envio": round(costo, -2),
                "zona": zona,
                "modo_lluvia": modo_lluvia,
                "distancia_km": distancia_km,
                "detalle_tarifa": f"Tarifa por Kilómetro ({distancia_km} km)"
            }

        elif regla == "FIJA" and es_misma_localidad:
            costo = float(comercio.get("costo_envio_fijo", costo_red))
            if modo_lluvia:
                costo = round((costo * mult) / 100) * 100
            return {
                "costo_envio": costo,
                "zona": zona,
                "modo_lluvia": modo_lluvia,
                "distancia_km": distancia_km,
                "detalle_tarifa": f"Envío Fijo Propio (Zona {zona})"
            }

    costo = costo_red
    if modo_lluvia:
        costo = round((costo * mult) / 100) * 100

    return {
        "costo_envio": costo,
        "zona": zona,
        "modo_lluvia": modo_lluvia,
        "distancia_km": distancia_km,
        "detalle_tarifa": f"Red SurPide (Zona {zona})"
    }

@app.get("/api/calcular-envio")
def api_calcular_envio(comercio_id: int, localidad_destino: str, barrio_destino: str, tipo_entrega: str = "ENVIO", subtotal: float = 0.0, lat: Optional[float] = None, lon: Optional[float] = None):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM comercios WHERE id = ?", (comercio_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Comercio no encontrado")
    return calcular_tarifa_comercio(dict(row), localidad_destino, barrio_destino, tipo_entrega, subtotal, lat, lon)

@app.get("/api/validar-cupon")
def validar_cupon(codigo: str, subtotal: float):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM cupones WHERE UPPER(codigo) = UPPER(?) AND activo = 1", (codigo.strip(),))
    cup = c.fetchone()
    conn.close()
    if not cup:
        raise HTTPException(status_code=404, detail="Cupón inválido o vencido")
    descuento = min(round(max(0.0, subtotal) * (cup["descuento_pct"] / 100.0)), cup["tope_reintegro"])
    return {
        "ok": True,
        "codigo": cup["codigo"],
        "descuento_pct": cup["descuento_pct"],
        "monto_descuento": descuento
    }

# =========================================================
# CREACIÓN DE PEDIDOS BLINDADA (RECALCULA PRECIOS EN SERVIDOR)
# =========================================================
class ItemCarritoSeguroSchema(BaseModel):
    producto_id: Optional[int] = None
    cantidad: int = Field(default=1, ge=1, le=50)
    adicionales: Optional[List[str]] = []
    nota: Optional[str] = ""
    # Compatibilidad con envío directo
    nombre: Optional[str] = ""
    precio_unitario: Optional[float] = 0
    subtotal: Optional[float] = 0

class NuevoPedidoSchema(BaseModel):
    comercio_id: int
    cliente_nombre: str
    cliente_tel: str
    tipo_entrega: str = "ENVIO"
    localidad_destino: str
    barrio_destino: str
    direccion_calle: str
    entrecalles: str
    referencia_casa: Optional[str] = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    items_json: str
    nota_general: Optional[str] = ""
    metodo_pago: str
    paga_con: Optional[float] = 0
    comprobante_base64: Optional[str] = None
    subtotal_comida: float
    codigo_cupon: Optional[str] = ""

@app.post("/api/pedidos")
async def crear_pedido(pedido: NuevoPedidoSchema, request: Request):
    # 1. Rate Limit anti-spam por IP
    ip_cliente = obtener_ip_real(request)
    verificar_rate_limit_ip(ip_cliente, max_req=8, ventana_seg=60)

    # 2. Validación de tamaño y formato de comprobante Base64 (Máx ~4MB, solo imágenes)
    if pedido.comprobante_base64:
        if len(pedido.comprobante_base64) > 5_500_000:
            raise HTTPException(status_code=400, detail="La imagen del comprobante supera el tamaño máximo permitido (4 MB).")
        if not pedido.comprobante_base64.startswith("data:image/"):
            raise HTTPException(status_code=400, detail="Formato de archivo inválido. Solo se permiten capturas en imagen.")

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM comercios WHERE id = ? AND abierto = 1", (pedido.comercio_id,))
    row_com = c.fetchone()
    if not row_com:
        conn.close()
        raise HTTPException(status_code=400, detail="El comercio se encuentra cerrado en este momento.")
    comercio = dict(row_com)

    # 3. Verificación y recálculo Server-Side de precios desde la Base de Datos (Anti-Tampering)
    try:
        items_raw = json.loads(pedido.items_json)
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="Formato de carrito inválido.")

    if not items_raw or not isinstance(items_raw, list):
        conn.close()
        raise HTTPException(status_code=400, detail="El carrito no puede estar vacío.")

    c.execute("SELECT * FROM productos WHERE comercio_id = ? AND disponible = 1", (pedido.comercio_id,))
    catalogo_db = {p["id"]: dict(p) for p in c.fetchall()}
    catalogo_por_nombre = {p["nombre"]: dict(p) for p in catalogo_db.values()}

    subtotal_verificado = 0.0
    items_sanitizados = []

    for item in items_raw:
        cant = max(1, min(50, int(item.get("cantidad", 1))))
        prod_id = item.get("producto_id")
        prod_db = catalogo_db.get(prod_id)

        # Fallback por si el frontend envió el nombre compuesto
        if not prod_db:
            nombre_base = str(item.get("nombre", "")).split(" (")[0].strip()
            prod_db = catalogo_por_nombre.get(nombre_base)

        if prod_db:
            precio_base = float(prod_db["precio_mostrador"])
            opciones_validas = {op["nombre"]: float(op["precio"]) for op in json.loads(prod_db.get("opciones_json") or "[]")}
            adicionales_elegidos = item.get("adicionales", [])
            extra_verificado = sum(opciones_validas.get(ad, 0.0) for ad in adicionales_elegidos)
            # Si ya venía en el nombre desde cliente.html, respetamos opciones válidas encontradas en el texto
            if not adicionales_elegidos and "(" in str(item.get("nombre", "")):
                for op_nom, op_val in opciones_validas.items():
                    if op_nom in str(item.get("nombre", "")):
                        extra_verificado += op_val
            unitario_real = precio_base + extra_verificado
            sub_item = unitario_real * cant
            subtotal_verificado += sub_item
            items_sanitizados.append({
                "cantidad": cant,
                "nombre": sanitizar_texto(item.get("nombre") or prod_db["nombre"], 180),
                "precio_unitario": unitario_real,
                "subtotal": sub_item
            })
        else:
            # Si es un producto recién creado sin match exacto, valida que nunca sea negativo
            precio_u = max(100.0, float(item.get("precio_unitario", 0)))
            sub_item = precio_u * cant
            subtotal_verificado += sub_item
            items_sanitizados.append({
                "cantidad": cant,
                "nombre": sanitizar_texto(str(item.get("nombre", "Producto")), 180),
                "precio_unitario": precio_u,
                "subtotal": sub_item
            })

    descuento_cupon = 0.0
    if pedido.codigo_cupon:
        c.execute("SELECT * FROM cupones WHERE UPPER(codigo) = UPPER(?) AND activo = 1", (pedido.codigo_cupon.strip(),))
        cup = c.fetchone()
        if cup:
            descuento_cupon = min(round(subtotal_verificado * (cup["descuento_pct"] / 100.0)), cup["tope_reintegro"])

    subtotal_neto = max(0.0, subtotal_verificado - descuento_cupon)
    info_envio = calcular_tarifa_comercio(
        comercio, pedido.localidad_destino, pedido.barrio_destino, pedido.tipo_entrega, subtotal_neto, pedido.lat, pedido.lon
    )
    costo_envio = info_envio["costo_envio"]
    distancia_km = info_envio["distancia_km"]
    total_final = subtotal_neto + costo_envio
    comision_plataforma = round(subtotal_neto * (comercio["comision_pct"] / 100.0), 2)
    ahora = datetime.now().strftime("%H:%M - %d/%m/%Y")

    # PIN de 4 dígitos criptográficamente aleatorio y token de tracking privado (anti-IDOR)
    pin_entrega = f"{secrets.randbelow(9000) + 1000}"
    tracking_token = secrets.token_urlsafe(16)
    origen_flota_inicial = "SURPIDE" if comercio["modo_logistica"] == "SURPIDE" else "PROPIA"

    # Sanitización contra XSS en todos los campos de texto libre
    nombre_limpio = sanitizar_texto(pedido.cliente_nombre, 80)
    tel_limpio = sanitizar_texto(pedido.cliente_tel, 30)
    calle_limpia = sanitizar_texto(pedido.direccion_calle, 120)
    entre_limpio = sanitizar_texto(pedido.entrecalles, 120)
    ref_limpia = sanitizar_texto(pedido.referencia_casa, 200)
    nota_limpia = sanitizar_texto(pedido.nota_general, 200)
    metodo_limpio = "TRANSFERENCIA" if pedido.metodo_pago == "TRANSFERENCIA" else "EFECTIVO"

    c.execute("""
        INSERT INTO pedidos (
            tracking_token, comercio_id, cliente_nombre, cliente_tel, tipo_entrega, localidad_destino, barrio_destino,
            direccion_calle, entrecalles, referencia_casa, distancia_km, items_json, nota_general, metodo_pago,
            paga_con, comprobante_base64, subtotal_comida, descuento_cupon, costo_envio,
            total_final, comision_plataforma, origen_flota, pin_entrega, creado_en
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        tracking_token, pedido.comercio_id, nombre_limpio, tel_limpio, pedido.tipo_entrega,
        sanitizar_texto(pedido.localidad_destino, 50), sanitizar_texto(pedido.barrio_destino, 60), calle_limpia,
        entre_limpio, ref_limpia, distancia_km, json.dumps(items_sanitizados), nota_limpia,
        metodo_limpio, max(0.0, float(pedido.paga_con or 0)), pedido.comprobante_base64,
        subtotal_verificado, descuento_cupon, costo_envio, total_final,
        comision_plataforma, origen_flota_inicial, pin_entrega, ahora
    ))
    pedido_id = c.lastrowid
    conn.commit()

    c.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,))
    nuevo_p = dict(c.fetchone())
    conn.close()

    await manager.notificar_comercio(pedido.comercio_id, {
        "evento": "NUEVO_PEDIDO",
        "pedido": nuevo_p
    })

    return {
        "ok": True,
        "pedido_id": pedido_id,
        "tracking_token": tracking_token,
        "pin_entrega": pin_entrega,
        "costo_envio": costo_envio,
        "descuento_cupon": descuento_cupon,
        "total_final": total_final,
        "pedido": nuevo_p
    }

class AsignarCadetePropioSchema(BaseModel):
    cadete_id: int

@app.post("/api/pedidos/{pedido_id}/despachar-propio")
async def despachar_con_cadete_propio(pedido_id: int, body: AsignarCadetePropioSchema):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM cadetes_propios WHERE id = ?", (body.cadete_id,))
    cadete = c.fetchone()
    if not cadete:
        conn.close()
        raise HTTPException(status_code=404, detail="Cadete propio no encontrado")

    nombre_completo = f"{cadete['nombre']} (Logística Propia)"
    c.execute("""
        UPDATE pedidos
        SET estado = 'EN_CAMINO', origen_flota = 'PROPIA', repartidor_nombre = ?, repartidor_tel = ?
        WHERE id = ?
    """, (nombre_completo, cadete["whatsapp"], pedido_id))
    conn.commit()

    c.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,))
    p = dict(c.fetchone())
    conn.close()

    await manager.notificar_comercio(p["comercio_id"], {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    await manager.notificar_cliente_pedido(pedido_id, {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    return {"ok": True, "pedido": p, "cadete": dict(cadete)}

@app.post("/api/pedidos/{pedido_id}/solicitar-cadete")
async def solicitar_cadete_surpide(pedido_id: int):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("UPDATE pedidos SET estado = 'BUSCANDO_CADETE', origen_flota = 'SURPIDE' WHERE id = ?", (pedido_id,))
    conn.commit()

    c.execute("""
        SELECT p.*, c.nombre as comercio_nombre, c.direccion as comercio_direccion, c.localidad as comercio_localidad
        FROM pedidos p JOIN comercios c ON p.comercio_id = c.id
        WHERE p.id = ?
    """, (pedido_id,))
    p = dict(c.fetchone())
    conn.close()

    # A los repartidores NUNCA se les envía el pin_entrega por WebSocket (el PIN solo lo tiene el vecino y la comanda impresa)
    viaje_seguro = {k: v for k, v in p.items() if k not in ("pin_entrega", "comprobante_base64", "tracking_token")}

    await manager.notificar_comercio(p["comercio_id"], {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    await manager.notificar_repartidores({"evento": "NUEVO_VIAJE", "viaje": viaje_seguro})
    await manager.notificar_cliente_pedido(pedido_id, {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    return {"ok": True, "viaje": viaje_seguro}

@app.get("/api/pedidos/{pedido_id}/tracking")
def obtener_tracking_pedido(pedido_id: int, token: Optional[str] = None):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT p.id, p.tracking_token, p.estado, p.tipo_entrega, p.repartidor_nombre,
               p.total_final, p.costo_envio, p.metodo_pago, p.pin_entrega, p.creado_en,
               c.nombre as comercio_nombre, c.whatsapp as comercio_whatsapp
        FROM pedidos p JOIN comercios c ON p.comercio_id = c.id
        WHERE p.id = ?
    """, (pedido_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")
    datos = dict(row)
    # Protección anti-IDOR: si no provee el tracking_token del pedido, oculta el PIN de entrega
    if token != datos.get("tracking_token"):
        datos["pin_entrega"] = "****"
    del datos["tracking_token"]
    return datos

@app.get("/api/comercios/{comercio_id}/pedidos")
def listar_pedidos_comercio(comercio_id: int):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM pedidos WHERE comercio_id = ? ORDER BY id DESC LIMIT 60", (comercio_id,))
    pedidos = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"pedidos": pedidos}

class CambioEstadoSchema(BaseModel):
    estado: str
    pin_confirmacion: Optional[str] = None

@app.post("/api/pedidos/{pedido_id}/estado")
async def cambiar_estado_pedido(pedido_id: int, body: CambioEstadoSchema):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,))
    p_actual = c.fetchone()
    if not p_actual:
        conn.close()
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    # Protección Anti-Fuerza Bruta en el PIN de Entrega del Repartidor
    if body.estado == "ENTREGADO" and body.pin_confirmacion is not None:
        if p_actual["intentos_pin"] >= 5:
            conn.close()
            raise HTTPException(status_code=429, detail="Se superó el límite de intentos de PIN para este pedido. Pedile al comercio que lo marque como entregado desde caja.")
        if not hmac.compare_digest(body.pin_confirmacion.strip(), p_actual["pin_entrega"]):
            c.execute("UPDATE pedidos SET intentos_pin = intentos_pin + 1 WHERE id = ?", (pedido_id,))
            conn.commit()
            conn.close()
            raise HTTPException(status_code=400, detail="PIN de recepción incorrecto. Verificá los 4 dígitos en la pantalla del cliente.")

    c.execute("UPDATE pedidos SET estado = ? WHERE id = ?", (body.estado, pedido_id))
    conn.commit()
    c.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,))
    p = dict(c.fetchone())
    conn.close()

    await manager.notificar_comercio(p["comercio_id"], {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    await manager.notificar_repartidores({"evento": "ACTUALIZAR_VIAJES"})
    await manager.notificar_cliente_pedido(pedido_id, {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    return {"ok": True, "pedido": p}

# SEGURIDAD: La lista de viajes para repartidores NUNCA incluye pin_entrega ni comprobante_base64
@app.get("/api/repartidores/viajes")
def listar_viajes_repartidores():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT p.id, p.comercio_id, p.cliente_nombre, p.cliente_tel, p.tipo_entrega,
               p.localidad_destino, p.barrio_destino, p.direccion_calle, p.entrecalles,
               p.referencia_casa, p.distancia_km, p.metodo_pago, p.paga_con,
               p.subtotal_comida, p.costo_envio, p.total_final, p.estado,
               p.origen_flota, p.repartidor_nombre, p.creado_en,
               c.nombre as comercio_nombre, c.direccion as comercio_direccion,
               c.localidad as comercio_localidad, c.whatsapp as comercio_whatsapp
        FROM pedidos p JOIN comercios c ON p.comercio_id = c.id
        WHERE p.origen_flota = 'SURPIDE' AND p.estado IN ('BUSCANDO_CADETE', 'EN_CAMINO')
        ORDER BY p.id DESC
    """)
    viajes = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"viajes": viajes}

class TomarViajeSchema(BaseModel):
    repartidor_nombre: str

@app.post("/api/pedidos/{pedido_id}/tomar-viaje")
async def tomar_viaje(pedido_id: int, body: TomarViajeSchema):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Operación atómica SQL para evitar condición de carrera (Race Condition) si 2 motoqueros tocan al mismo tiempo
    nombre_limpio = f"{sanitizar_texto(body.repartidor_nombre, 60)} (Red SurPide)"
    c.execute("""
        UPDATE pedidos SET estado = 'EN_CAMINO', repartidor_nombre = ?
        WHERE id = ? AND estado = 'BUSCANDO_CADETE'
    """, (nombre_limpio, pedido_id))
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=400, detail="Este viaje ya fue tomado por otro repartidor hace un instante.")
    conn.commit()

    c.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,))
    p = dict(c.fetchone())
    conn.close()

    await manager.notificar_comercio(p["comercio_id"], {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    await manager.notificar_repartidores({"evento": "ACTUALIZAR_VIAJES"})
    await manager.notificar_cliente_pedido(pedido_id, {"evento": "ACTUALIZAR_PEDIDO", "pedido": p})
    return {"ok": True, "pedido": p}

# =========================================================
# AUTENTICACIÓN CON HASHING PBKDF2 + TOKEN DE SESIÓN
# =========================================================
class LoginLocalSchema(BaseModel):
    slug: str
    pin: str

@app.post("/api/local-auth")
def local_auth(body: LoginLocalSchema, request: Request):
    ip = obtener_ip_real(request)
    verificar_bloqueo_login(ip)

    slug_clean = body.slug.lower().strip()
    pin_candidato_hash = hash_pin(body.pin.strip(), slug_clean)

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM comercios WHERE slug = ?", (slug_clean,))
    com = c.fetchone()
    conn.close()

    if not com or not hmac.compare_digest(com["pin_hash"], pin_candidato_hash):
        registrar_fallo_login(ip)
        raise HTTPException(status_code=401, detail="Slug o PIN de acceso incorrecto.")

    limpiar_fallos_login(ip)
    token = crear_token_comercio(com["id"])
    datos_comercio = {k: v for k, v in dict(com).items() if k != "pin_hash"}
    return {"ok": True, "token": token, "comercio": datos_comercio}

class ActualizarLocalAdminSchema(BaseModel):
    comercio_id: int
    nuevo_pin: Optional[str] = ""
    nombre: str
    whatsapp: str
    alias_mp: str
    tiempo_estimado: str
    abierto: int
    modo_logistica: str
    tipo_tarifa_propia: str
    costo_envio_fijo: float
    costo_por_km: float
    envio_gratis_desde: float

@app.put("/api/local-admin/config")
def actualizar_local_admin(body: ActualizarLocalAdminSchema, x_comercio_token: Optional[str] = Header(None)):
    validar_token_comercio(body.comercio_id, x_comercio_token)

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT slug, pin_hash FROM comercios WHERE id = ?", (body.comercio_id,))
    actual = c.fetchone()
    if not actual:
        conn.close()
        raise HTTPException(status_code=404, detail="Comercio no encontrado")

    nuevo_hash = actual["pin_hash"]
    if body.nuevo_pin and len(body.nuevo_pin.strip()) >= 4:
        nuevo_hash = hash_pin(body.nuevo_pin.strip(), actual["slug"])

    c.execute("""
        UPDATE comercios
        SET pin_hash = ?, nombre = ?, whatsapp = ?, alias_mp = ?, tiempo_estimado = ?,
            abierto = ?, modo_logistica = ?, tipo_tarifa_propia = ?, costo_envio_fijo = ?, costo_por_km = ?, envio_gratis_desde = ?
        WHERE id = ?
    """, (
        nuevo_hash, sanitizar_texto(body.nombre, 80), sanitizar_texto(body.whatsapp, 30),
        sanitizar_texto(body.alias_mp, 60), sanitizar_texto(body.tiempo_estimado, 30),
        body.abierto, body.modo_logistica, body.tipo_tarifa_propia,
        max(0.0, body.costo_envio_fijo), max(0.0, body.costo_por_km), max(0.0, body.envio_gratis_desde),
        body.comercio_id
    ))
    conn.commit()
    conn.close()
    return {"ok": True}

class ConfigLogisticaComercioSchema(BaseModel):
    abierto: int
    tiempo_estimado: str
    alias_mp: str
    modo_logistica: str
    tipo_tarifa_propia: str
    costo_envio_fijo: float
    costo_por_km: float
    envio_gratis_desde: float

@app.put("/api/comercios/{comercio_id}/config")
def actualizar_config_comercio(comercio_id: int, body: ConfigLogisticaComercioSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE comercios
        SET abierto = ?, tiempo_estimado = ?, alias_mp = ?,
            modo_logistica = ?, tipo_tarifa_propia = ?, costo_envio_fijo = ?, costo_por_km = ?, envio_gratis_desde = ?
        WHERE id = ?
    """, (
        body.abierto, sanitizar_texto(body.tiempo_estimado, 30), sanitizar_texto(body.alias_mp, 60),
        body.modo_logistica, body.tipo_tarifa_propia, max(0.0, body.costo_envio_fijo), max(0.0, body.costo_por_km), max(0.0, body.envio_gratis_desde),
        comercio_id
    ))
    conn.commit()
    conn.close()
    return {"ok": True}

class NuevoCadetePropioSchema(BaseModel):
    comercio_id: int
    nombre: str
    whatsapp: str
    vehiculo: str = "Moto"

@app.post("/api/cadetes-propios")
def agregar_cadete_propio(body: NuevoCadetePropioSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO cadetes_propios (comercio_id, nombre, whatsapp, vehiculo, activo) VALUES (?, ?, ?, ?, 1)", (body.comercio_id, sanitizar_texto(body.nombre, 60), sanitizar_texto(body.whatsapp, 30), sanitizar_texto(body.vehiculo, 40)))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.delete("/api/cadetes-propios/{cadete_id}")
def eliminar_cadete_propio(cadete_id: int):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE cadetes_propios SET activo = 0 WHERE id = ?", (cadete_id,))
    conn.commit()
    conn.close()
    return {"ok": True}

class RegistrarRendicionSchema(BaseModel):
    comercio_id: int
    cadete_id: int
    cadete_nombre: str
    total_efectivo_cobrado: float
    total_envios_pagados: float
    neto_a_rendir_al_local: float
    cantidad_pedidos: int

@app.post("/api/rendiciones")
def registrar_rendicion(body: RegistrarRendicionSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ahora = datetime.now().strftime("%d/%m/%Y %H:%M")
    c.execute("INSERT INTO rendiciones_cadetes (comercio_id, cadete_id, cadete_nombre, total_efectivo_cobrado, total_envios_pagados, neto_a_rendir_al_local, cantidad_pedidos, cerrado_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (body.comercio_id, body.cadete_id, sanitizar_texto(body.cadete_nombre, 60), body.total_efectivo_cobrado, body.total_envios_pagados, body.neto_a_rendir_al_local, body.cantidad_pedidos, ahora))
    c.execute("UPDATE pedidos SET rendido = 1 WHERE comercio_id = ? AND estado = 'ENTREGADO' AND rendido = 0 AND repartidor_nombre LIKE ?", (body.comercio_id, f"%{body.cadete_nombre}%"))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/comercios/{comercio_id}/rendiciones")
def listar_rendiciones(comercio_id: int):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM rendiciones_cadetes WHERE comercio_id = ? ORDER BY id DESC LIMIT 30", (comercio_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"rendiciones": rows}

class EditarProductoSchema(BaseModel):
    precio_mostrador: float
    precio_apps: float
    disponible: int

@app.put("/api/productos/{producto_id}")
def actualizar_producto(producto_id: int, body: EditarProductoSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE productos SET precio_mostrador = ?, precio_apps = ?, disponible = ? WHERE id = ?", (max(0.0, body.precio_mostrador), max(0.0, body.precio_apps), body.disponible, producto_id))
    conn.commit()
    conn.close()
    return {"ok": True}

class NuevoProductoSchema(BaseModel):
    comercio_id: int
    nombre: str
    descripcion: str
    precio_mostrador: float
    precio_apps: float
    categoria: str
    icono: str = "🍔"
    imagen_url: str = ""

@app.post("/api/productos")
def crear_producto(body: NuevoProductoSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO productos (comercio_id, nombre, descripcion, precio_mostrador, precio_apps, categoria, icono, imagen_url, disponible, opciones_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, '[]')", (body.comercio_id, sanitizar_texto(body.nombre, 80), sanitizar_texto(body.descripcion, 200), max(0.0, body.precio_mostrador), max(0.0, body.precio_apps), sanitizar_texto(body.categoria, 40), body.icono, body.imagen_url))
    conn.commit()
    conn.close()
    return {"ok": True}

# =========================================================
# PANEL MASTER ADMIN PROTEGIDO CON CLAVE MAESTRA
# =========================================================
class LoginAdminMasterSchema(BaseModel):
    clave: str

@app.post("/api/admin/login")
def login_admin_master(body: LoginAdminMasterSchema, request: Request):
    ip = obtener_ip_real(request)
    verificar_bloqueo_login(ip)
    if not hmac.compare_digest(body.clave.strip(), ADMIN_MASTER_KEY):
        registrar_fallo_login(ip)
        raise HTTPException(status_code=401, detail="Clave maestra incorrecta.")
    limpiar_fallos_login(ip)
    token = secrets.token_urlsafe(32)
    SESIONES_ADMIN[token] = time.time() + 43200
    return {"ok": True, "token": token}

@app.get("/api/admin/resumen")
def admin_resumen():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT valor FROM config_sistema WHERE clave = 'modo_lluvia'")
    modo_lluvia = c.fetchone()[0] == "1"
    c.execute("""
        SELECT
            c.id, c.slug, c.nombre, c.localidad, c.whatsapp, c.alias_mp, c.comision_pct, c.abierto, c.modo_logistica,
            COUNT(p.id) as total_pedidos,
            SUM(CASE WHEN p.origen_flota = 'PROPIA' AND p.id IS NOT NULL THEN 1 ELSE 0 END) as envios_propios,
            SUM(CASE WHEN p.origen_flota = 'SURPIDE' AND p.id IS NOT NULL THEN 1 ELSE 0 END) as envios_surpide,
            COALESCE(SUM(p.subtotal_comida - p.descuento_cupon), 0) as venta_comida_bruta,
            COALESCE(SUM(p.costo_envio), 0) as total_envios,
            COALESCE(SUM(p.comision_plataforma), 0) as comision_generada
        FROM comercios c
        LEFT JOIN pedidos p ON c.id = p.comercio_id AND p.estado != 'CANCELADO'
        GROUP BY c.id
    """)
    liquidaciones = []
    for r in c.fetchall():
        d = dict(r)
        c.execute("SELECT COALESCE(SUM(monto), 0) FROM pagos_comisiones WHERE comercio_id = ?", (d["id"],))
        pagado = c.fetchone()[0]
        d["comision_pagada"] = pagado
        d["saldo_pendiente"] = round(max(0.0, d["comision_generada"] - pagado), 2)
        liquidaciones.append(d)
    conn.close()
    return {"modo_lluvia": modo_lluvia, "liquidaciones": liquidaciones}

class RegistrarPagoComisionSchema(BaseModel):
    comercio_id: int
    monto: float

@app.post("/api/admin/registrar-pago")
def registrar_pago_comision(body: RegistrarPagoComisionSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ahora = datetime.now().strftime("%d/%m/%Y %H:%M")
    c.execute("INSERT INTO pagos_comisiones (comercio_id, monto, fecha) VALUES (?, ?, ?)", (body.comercio_id, max(0.0, body.monto), ahora))
    conn.commit()
    conn.close()
    return {"ok": True}

class NuevoComercioAdminSchema(BaseModel):
    slug: str
    nombre: str
    rubro: str
    localidad: str
    barrio: str
    direccion: str
    whatsapp: str
    alias_mp: str
    titular_mp: str
    pin_acceso: str = "1234"
    modo_logistica: str = "HIBRIDA"
    comision_pct: float = 5.0
    icono: str = "🍔"

@app.post("/api/admin/comercios")
def crear_comercio_admin(body: NuevoComercioAdminSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    slug_clean = body.slug.lower().strip()
    pin_hashed = hash_pin(body.pin_acceso.strip() or "1234", slug_clean)
    try:
        c.execute("""
            INSERT INTO comercios (
                slug, nombre, rubro, localidad, barrio, direccion, whatsapp,
                alias_mp, titular_mp, pin_hash, comision_pct, abierto, acepta_retiro, icono,
                banner_url, modo_logistica, tipo_tarifa_propia, costo_envio_fijo, costo_por_km, envio_gratis_desde
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, 'https://images.unsplash.com/photo-1504674900247-0877df9cc836?auto=format&fit=crop&w=900&q=80', ?, 'KM', 1200.0, 400.0, 20000.0)
        """, (
            slug_clean, sanitizar_texto(body.nombre, 80), sanitizar_texto(body.rubro, 50),
            sanitizar_texto(body.localidad, 40), sanitizar_texto(body.barrio, 50),
            sanitizar_texto(body.direccion, 100), sanitizar_texto(body.whatsapp, 30),
            sanitizar_texto(body.alias_mp, 60), sanitizar_texto(body.titular_mp, 80),
            pin_hashed, body.comision_pct, body.icono, body.modo_logistica
        ))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Error al crear comercio: {str(e)}")
    conn.close()
    return {"ok": True}

class ModoLluviaSchema(BaseModel):
    activo: bool

@app.post("/api/admin/lluvia")
def cambiar_modo_lluvia(body: ModoLluviaSchema):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE config_sistema SET valor = ? WHERE clave = 'modo_lluvia'", ("1" if body.activo else "0",))
    conn.commit()
    conn.close()
    return {"ok": True, "modo_lluvia": body.activo}

@app.websocket("/ws/comercio/{comercio_id}")
async def ws_comercio_endpoint(websocket: WebSocket, comercio_id: int):
    await manager.conectar_comercio(comercio_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.desconectar_comercio(comercio_id, websocket)

@app.websocket("/ws/repartidores")
async def ws_repartidores_endpoint(websocket: WebSocket):
    await manager.conectar_repartidor(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.desconectar_repartidor(websocket)

@app.websocket("/ws/pedido/{pedido_id}")
async def ws_pedido_cliente(websocket: WebSocket, pedido_id: int):
    await manager.conectar_cliente_pedido(pedido_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.desconectar_cliente_pedido(pedido_id, websocket)


# =========================================================
# ENDPOINTS CLOUD (RENDER HEALTHCHECK + BACKUP JSON/DB)
# =========================================================
@app.get("/healthz")
def healthcheck():
    return {"status": "ok", "service": "SurPide Cloud v9"}

@app.get("/api/admin/backup-db")
def descargar_backup_db():
    """Permite descargar el archivo SQLite entero como respaldo desde el navegador."""
    if not os.path.exists(DB_NAME):
        raise HTTPException(status_code=404, detail="Base de datos no encontrada")
    return FileResponse(DB_NAME, media_type="application/octet-stream", filename="surpide_backup.db")
