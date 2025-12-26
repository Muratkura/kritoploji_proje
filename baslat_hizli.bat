@echo off
chcp 65001 >nul
title Şifreleme Uygulaması - Hızlı Başlatma
color 0A

echo.
echo Şifreleme Uygulaması başlatılıyor...
echo Tarayıcınızda http://localhost:5000 adresini açın
echo.
echo Çıkmak için bu pencereyi kapatın veya Ctrl+C tuşlarına basın
echo.

python app.py

pause

