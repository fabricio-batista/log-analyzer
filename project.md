O foco principal desse projeto é analise de Android logcat + dmesg, tool via cli.

Estrutura inicial do projeto:

log-analyzer/
├── log_analyzer.py
├── collectors/ --> captura de logs
│   ├── adb_logcat.py
```bash
    Responsável por rodar comandos como:
        adb logcat -d
        adb logcat -c
        adb logcat --pid <PID>
        adb shell pidof com.example.app
```
│   └── adb_dmesg.py
```bash
    Responsável por rodar "adb shell dmesg"

    Em caso de falha:
    "[!] Não foi possível capturar dmesg.
    Possíveis causas:
    - dispositivo sem root
    - kernel restringe acesso ao dmesg
    - build user com permissões limitadas"
```
├── parsers/
│   ├── android_logcat.py
```bash
    {
        "source": "logcat",
        "timestamp": "06-20 10:15:32.123",
        "pid": "1234",
        "tid": "5678",
        "level": "E",
        "tag": "AndroidRuntime",
        "message": "FATAL EXCEPTION: main",
        "raw": "06-20 10:15:32.123  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main"
    }
```
│   ├── dmesg.py
```bash
    {
        "source": "dmesg",
        "kernel_time": "1234.567890",
        "message": "audit: avc: denied { read } for ...",
        "raw": "[ 1234.567890] audit: avc: denied { read } for ..."
    }
```
│   ├── apache.py
│   ├── nginx.py
│   └── generic.py
├── detectors/
│   ├── android_sensitive_data.py
```bash
    Procuraria por padrões como:
    password
    passwd
    pwd
    token
    access_token
    refresh_token
    authorization
    bearer
    jwt
    api_key
    apikey
    secret
    client_secret
    session
    cookie
    cpf
    email
    phone
    imei
    android_id
    firebase
```
            
│   ├── android_crashes.py
```bash
    Detecta crashes e exceções.
    Padrões:

    FATAL EXCEPTION
    AndroidRuntime
    NullPointerException
    IllegalStateException
    SecurityException
    ActivityNotFoundException
    ClassNotFoundException
    ANR
    Input dispatching timed out
    Force finishing activity
```
│   ├── android_security.py
```bash
    Detecta eventos interessantes de segurança no logcat.
    Padrões:

    Permission Denial
    SecurityException
    not exported from uid
    requires permission
    Permission denied
    SELinux
    avc: denied
    Cleartext HTTP traffic
    Trust anchor for certification path not found
    SSLHandshakeException
    CertPathValidatorException
    NetworkSecurityConfig
    BiometricPrompt
    KeyStore
    EncryptedSharedPreferences
```
│   ├── kernel_security.py
```bash
    Focado em dmesg.
    Padrões:

    avc: denied
    SELinux
    audit
    capability
    denied
    segfault
    crash
    panic
    oops
    init:
    service exited
    killed
    lowmemorykiller
    binder
```
│   ├── brute_force.py
│   ├── directory_scan.py
│   ├── sqli.py
│   ├── xss.py
│   └── lfi.py
├── reports/
│   └── report_generator.py
└── output/
    └── report.json


1. Ela deve funcionar em dois cenários:
    1. Analisar um arquivo de log já salvo
    2. Capturar logs direto do dispositivo Android via adb


**Exemplos de uso:**

```bash
    python log_analyzer.py --file logs/logcat.txt --type logcat
```
```bash
    python log_analyzer.py --capture-logcat
```
```bash
    python log_analyzer.py --capture-dmesg
```
```bash
    python log_analyzer.py --capture-logcat --package com.example.app
```
```bash
    python log_analyzer.py --file logs/dmesg.txt --type dmesg
```
```bash
    python log_analyzer.py --file logs/logcat.txt --type logcat --terms token password api_key
```





MVP + futuras versões:
Versão 0.1
- Analisar arquivo logcat salvo
- Capturar logcat via adb
- Capturar dmesg via adb shell dmesg
- Parser básico de logcat
- Parser básico de dmesg
- Detector de dados sensíveis
- Detector de crashes
- Detector de eventos de segurança Android
- Detector de eventos de kernel/dmesg
- Relatório no terminal
- Relatório JSON


Versão 0.2
- Filtrar por package name
- Pegar PID automaticamente via adb shell pidof
- Rodar adb logcat --pid <PID>
- Modo interativo
- Modo --terms
- Modo --regex


Versão 0.3
- Suporte a Apache/Nginx/generic
- Detectores web: SQLi, XSS, LFI, directory scan
- Exportação CSV
- Score de severidade