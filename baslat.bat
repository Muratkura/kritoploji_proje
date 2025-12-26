@echo off
chcp 65001 >nul
title Şifreleme Uygulaması
color 0A

echo.
echo ========================================
echo   Şifreleme Uygulaması Başlatılıyor...
echo ========================================
echo.

REM Python'un yüklü olup olmadığını kontrol et
python --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadı!
    echo Lütfen Python'u yükleyin: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] Python kontrolü yapıldı...
echo.

REM Gerekli kütüphaneleri kontrol et ve yükle
echo [2/3] Gerekli kütüphaneler kontrol ediliyor...
python -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo [UYARI] Bazı kütüphaneler yüklenemedi. Devam ediliyor...
)
echo.

REM Flask uygulamasını başlat
echo [3/3] Flask uygulaması başlatılıyor...
echo.
echo ========================================
echo   Uygulama çalışıyor!
echo   Tarayıcınızda şu adresi açın:
echo   http://localhost:5000
echo ========================================
echo.
echo Çıkmak için Ctrl+C tuşlarına basın...
echo.

python app.py

pause

