cmake_minimum_required(VERSION 3.10)
project(VirusTotalScanner VERSION 1.0)

# Define o padrão C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Localizar pacotes no sistema (instalados via apt)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

# 2. Incluir o diretório de cabeçalhos (.hpp)
include_directories(include)

# 3. Listar os arquivos de implementação (.cpp)
set(SOURCES
    src/main.cpp
    src/Scanner.cpp
    src/Utils.cpp
)

# 4. Criar o executável na pasta bin (opcional, mas organizado)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
add_executable(vt_scanner ${SOURCES})

# 5. Linkar as bibliotecas externas ao executável
target_link_libraries(vt_scanner 
    PRIVATE 
    CURL::libcurl 
    OpenSSL::Crypto 
    nlohmann_json::nlohmann_json
)