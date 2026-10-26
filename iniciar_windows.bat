@echo off
title SurPide v9 CLOUD - Listo para Render y Local
echo =========================================================================
echo   Iniciando SurPide v9 CLOUD (Edicion Final para Render) en puerto 8000
echo =========================================================================
python -m pip install -r requirements.txt --quiet
echo.
echo -> Marketplace Cliente:          http://localhost:8000/
echo -> Admin Independiente Local:    http://localhost:8000/local-admin
echo -> Panel KDS Cocina:             http://localhost:8000/comercio
echo -> App Repartidores:             http://localhost:8000/repartidores
echo -> Panel Master Admin:           http://localhost:8000/admin
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
