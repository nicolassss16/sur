# 🚀 SurPide v9 CLOUD — Edición Final Lista para Render.com

Esta versión está configurada específicamente para subir a **GitHub** y desplegar en **Render.com** en 2 minutos.

## 🌐 Mejoras especiales para Render incluidas:
1. **`render.yaml` y `Procfile`**: Configuración automática de comando de inicio con `--proxy-headers` y puerto dinámico `$PORT`.
2. **Lectura de IP real detrás del Proxy de Render (`X-Forwarded-For`)**: Para que el límite anti-spam identifique a cada vecino por separado y no al balanceador de carga de Render.
3. **Keep-Alive de WebSockets (Ping automático cada 25s)**: Evita que Render corte la conexión en tiempo real de la pantalla KDS de cocina después de 60 segundos de silencio.
4. **Healthcheck (`/healthz`) y Botón de Backup de Base de Datos (`/api/admin/backup-db`)**: Para descargar una copia de seguridad de `surpide_prod.db` en 1 clic desde `/admin`.
