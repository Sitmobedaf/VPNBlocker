@echo off
chcp 65001
cd /d "%~dp0"
title VPNBlocker
java -Xmx256M -XX:+UseConcMarkSweepGC -XX:MaxGCPauseMillis=50 -Dfile.encoding=UTF-8 -jar PacketSniffer.jar
ping -n 5 127.0.0.1 >nul