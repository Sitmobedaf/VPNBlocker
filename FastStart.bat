@echo off
chcp 65001
cd /d "%~dp0"
title VPNBlocker
:Start
java -Xmx256M -XX:+UseConcMarkSweepGC -XX:MaxGCPauseMillis=50 -Dfile.encoding=UTF-8 -jar PacketSniffer.jar -f Stalkers39 0 5447,25565,80
echo Программа будет автоматически перезапущена через 5 секунд...
ping -n 5 127.0.0.1 >nul
Goto Start