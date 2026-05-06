#include "Scanner.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

Scanner::Scanner(const std::string &apiKey) : apiKey(apiKey)
{
}

void Scanner::processFile(const std::string &filePath)
{
  std::cout << "[+] Iniciando análise: " << filePath << std::endl;

  std::string hash = calculateSHA256(filePath);
  if (hash.empty())
  {
    std::cerr << "[-] Erro: Falha ao gerar hash. Verifique se o arquivo existe." << std::endl;
    return;
  }

  std::cout << "[-] SHA-256 calculando: " << hash << std::endl;

  // Próximo passo: getReport(hash)
}

std::string Scanner::calculateSHA256(const std::string &filePath)
{
  std::ifstream file(filePath, std::ios::binary);
  if (!file.is_open())
  {
    return "";
  }

  SHA256_CTX sha256;
  if (!SHA256_Init(&sha256))
  {
    return "";
  }

  const std::size_t bufferSize = 32768;
  char *buffer = new char[bufferSize];

  while (file.read(buffer, bufferSize) || file.gcount() > 0)
  {
    SHA256_Update(&sha256, buffer, file.gcount());
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &sha256);

  delete[] buffer;
  file.close();

  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return ss.str();
}

nlohmann::json Scanner::getReport(const std::string &hash) { return nullptr; }
bool Scanner::uploadFile(const std::string &filePath) { return false; }
void Scanner::displayResult(const nlohmann::json &report) {}