# VirusTotal Scanner C++

Ferramenta de linha de comando (CLI) desenvolvida em C++ para análise de integridade de arquivos utilizando a API do VirusTotal. 

## Objetivo do Projeto
Este projeto faz parte do meu portfólio de **Engenharia de Segurança**. O objetivo é demonstrar competência em:
- Integração com APIs REST de segurança.
- Manipulação de arquivos e cálculo de hashes criptográficos (SHA-256).
- Programação de sistemas em C++ com foco em performance e segurança.

## Arquitetura
- **C++17**: Linguagem principal.
- **libcurl**: Comunicação HTTP.
- **OpenSSL**: Processamento de Hash SHA-256.
- **nlohmann/json**: Manipulação de dados JSON.
- **CMake**: Sistema de build.

## Progresso do Desenvolvimento
- [x] Arquitetura de pastas e sistema de build (CMake).
- [x] CLI básica para recepção de argumentos.
- [x] **Motor de Hashing**: Implementação de leitura binária com buffer (32KB) e integração com OpenSSL para geração de hashes SHA-256.
- [x] **Integração com VirusTotal API v3**:
  - [x] Consultas automatizadas via libcurl.
  - [x] Tratamento de respostas JSON (nlohmann/json).
  - [x] Lógica de filtragem de resultados (Malicioso/Suspeito/Inofensivo).
- [x] **Upload Ativo**: Sistema de upload automático para arquivos inéditos usando `multipart/form-data` e `curl_mime`.

## Como clonar e preparar o ambiente
(Em breve: instruções de compilação para WSL/Ubuntu)
