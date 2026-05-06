#include "Scanner.hpp"
#include "Utils.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <curl/curl.h>

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

  std::cout << "[+] SHA-256 calculando: " << hash << std::endl;

  std::cout << "[*] Consultando VirusTotal..." << std::endl;
  nlohmann::json report = getReport(hash);

  if (report.contains("error") && report["error"]["code"] != "NotFoundError")
  {
    std::cerr << "[-] Erro na API: " << report["error"]["message"] << std::endl;
    return;
  }

  if (!report.contains("data"))
  {
    std::cout << "[!] Arquivo novo. Iniciando fluxo de upload..." << std::endl;
    // uploadFile(filePath);
    return;
  }

  std::cout << "[+] Relatório encontrado!" << std::endl;
  displayResult(report);
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

nlohmann::json Scanner::getReport(const std::string &hash)
{
  CURL *curl = curl_easy_init();
  std::string readBuffer;
  nlohmann::json responseJson;

  if (curl)
  {
    std::string url = "https://www.virustotal.com/api/v3/files/" + hash;

    struct curl_slist *headers = NULL;
    std::string authHeader = "x-apiKey: " + apiKey;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Utils::WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
      std::cerr << "[-] Erro na requisição: " << curl_easy_strerror(res) << std::endl;
    }
    else
    {
      try
      {
        responseJson = nlohmann::json::parse(readBuffer);
      }
      catch (const std::exception &e)
      {
        std::cerr << "[-] Erro ao processar JSON: " << e.what() << std::endl;
      }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  return responseJson;
}

void Scanner::displayResult(const nlohmann::json &report)
{
  auto stats = report["data"]["attributes"]["last_analysis_stats"];

  int malicious = stats["malicious"];
  int suspicious = stats["suspicious"];
  int harmless = stats["harmless"];

  std::cout << "\n=== RESUMO DA ANÁLISE ===" << std::endl;
  std::cout << "Maliciosos: " << malicious << std::endl;
  std::cout << "Suspeitos: " << suspicious << std::endl;
  std::cout << "Inofensivos: " << harmless << std::endl;
  std::cout << "\n=========================" << std::endl;

  if (malicious > 0)
  {
    std::cout << "ATENÇÃO: Este arquivo pode ser perigoso!" << std::endl;
  }
  else
  {
    std::cout << "Arquivo parece seguro com base no banco de dados atual." << std::endl;
  }
  std::cout << std::endl;
}

bool Scanner::uploadFile(const std::string &filePath) { return false; }