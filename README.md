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
- [x] **Análise em Tempo Real (Polling)**: Monitoramento automático do status de análise para novos uploads com tratamento de concorrência e timers.
- [x] **Gestão de Memória**: Implementação robusta contra Dangling Pointers e Memory Leaks em loops de rede.

## Como Clonar e Preparar o Ambiente (Ubuntu/WSL)

### Obtenção da API Key
Para utilizar esta ferramenta, é necessário possuir uma chave de autenticação oficial. Caso não possua uma, siga os passos abaixo:
1. Acesse o portal oficial do [VirusTotal](https://www.virustotal.com/).
2. Realize o cadastro ou efetue login em sua conta.
3. Navegue até o seu perfil de usuário e selecione a opção **"API Key"**.
4. Copie a sua chave privada disponível nesta seção. *Nota: A versão gratuita (Public API) possui limites de requisições por minuto.*

### Instalação e Execução
```bash
# 1. Instalar Dependências do Sistema
sudo apt update
sudo apt install build-essential cmake libcurl4-openssl-dev nlohmann-json3-dev libssl-dev

# 2. Clonar o Repositório
git clone [https://github.com/seu-usuario/VirusTotalScanner.git](https://github.com/seu-usuario/VirusTotalScanner.git)
cd VirusTotalScanner

# 3. Configurar a API Key (Substitua pela sua chave obtida no portal)
echo "VT_API_KEY=sua_chave_aqui" > .env

# 4. Compilação e Build
mkdir build && cd build
cmake ..
make

# 5. Como Testar e Usar (Arquivos Conhecidos)
./bin/vt_scanner /caminho/para/qualquer_arquivo_comum

# 6. Testar Fluxo de Upload e Polling (Arquivos Inéditos)
echo "Teste-Inedito-$(date)" > build/teste_unico.txt
./bin/vt_scanner build/teste_unico.txt
