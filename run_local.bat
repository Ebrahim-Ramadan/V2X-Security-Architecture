@echo off
echo ============================================
echo   V2X Security Architecture - Local Mode
echo   7 Vehicles + Dashboard (no Docker needed)
echo ============================================
echo.

echo Starting Dashboard...
start "Dashboard" cmd /k python dashboard/app.py
timeout /t 2 /nobreak > nul

echo Starting 7 vehicles...
start "Vehicle 1 - Car (72 km/h East)"         cmd /k python vehicles/vehicle.py --id 1
start "Vehicle 2 - Car (65 km/h East)"         cmd /k python vehicles/vehicle.py --id 2
start "Vehicle 3 - Truck (48 km/h West)"       cmd /k python vehicles/vehicle.py --id 3
start "Vehicle 4 - Car (80 km/h NE)"           cmd /k python vehicles/vehicle.py --id 4
start "Vehicle 5 - Emergency (110 km/h East)"  cmd /k python vehicles/vehicle.py --id 5
start "Vehicle 6 - Bus (38 km/h South)"        cmd /k python vehicles/vehicle.py --id 6
start "Vehicle 7 - Truck (44 km/h East)"       cmd /k python vehicles/vehicle.py --id 7

echo.
echo ============================================
echo   Dashboard:  http://localhost:8000
echo   Stats:      http://localhost:8000/stats
echo   Messages:   http://localhost:8000/messages
echo ============================================
echo.
echo All 8 windows opened. Close them manually to stop.
pause
