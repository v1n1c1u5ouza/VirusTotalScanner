#include "Scanner.hpp"
#include <iostream>

Scanner::Scanner(const std::string &apiKey) : apiKey(apiKey) 
{
}

void Scanner::processFile(const std::string &filePath)
{
    std::cout << "Processando: " << filePath << std::endl;
}

// Deixe as outras funções (calculateSHA256, etc) vazias por enquanto ou 
// apenas retornando valores padrão para o compilador não reclamar.
std::string Scanner::calculateSHA256(const std::string &filePath)
{
    return "";
}