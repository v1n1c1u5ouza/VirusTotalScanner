#include "Scanner.hpp"
#include "Utils.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <thread>
#include <chrono>

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
    std::cout << "[!] Arquivo não encontrado no VirusTotal." << std::endl;
    if (uploadFile(filePath))
    {
      std::cout << "[+] O arquivo foi enviado com sucesso para a fila de análise." << std::endl;
    }
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

CURL *Scanner::setupCurl(const std::string &url, std::string &responseBuffer, struct curl_slist *&headers)
{
  CURL *curl = curl_easy_init();
  if (!curl)
    return nullptr;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

  std::string authHeader = "x-apikey: " + apiKey;
  headers = curl_slist_append(headers, authHeader.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Utils::WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

  return curl;
}

nlohmann::json Scanner::getReport(const std::string &hash)
{
  std::string readBuffer;
  struct curl_slist *headers = NULL;
  std::string url = "https://www.virustotal.com/api/v3/files/" + hash;

  CURL *curl = setupCurl(url, readBuffer, headers);
  nlohmann::json responseJson;

  if (curl)
  {
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK)
    {
      try
      {
        responseJson = nlohmann::json::parse(readBuffer);
      }
      catch (...)
      {
      }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  return responseJson;
}

bool Scanner::uploadFile(const std::string &filePath)
{
  std::string readBuffer;
  struct curl_slist *headers = NULL;
  std::string url = "https://www.virustotal.com/api/v3/files";

  CURL *curl = setupCurl(url, readBuffer, headers);
  if (!curl)
    return false;

  bool success = false;

  curl_mime *mime = curl_mime_init(curl);
  curl_mimepart *part = curl_mime_addpart(mime);
  curl_mime_name(part, "file");
  curl_mime_filedata(part, filePath.c_str());
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

  std::cout << "[*] Enviando arquivo para análise..." << std::endl;
  CURLcode res = curl_easy_perform(curl);

  std::string analysisId;

  if (res != CURLE_OK)
  {
    std::cerr << "[-] Erro no upload: " << curl_easy_strerror(res) << std::endl;
    goto cleanup;
  }

  try
  {
    auto jsonResponse = nlohmann::json::parse(readBuffer);

    if (!jsonResponse.contains("data"))
    {
      goto cleanup;
    }

    analysisId = jsonResponse["data"]["id"];
    success = true;
  }
  catch (const std::exception &e)
  {
    std::cerr << "[-] Erro crítico ao processar resposta do servidor." << std::endl;
  }

cleanup:
  curl_mime_free(mime);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (success && !analysisId.empty()) {
    std::cerr << "[-] Resposta da API não contém dados de análise." << std::endl;
    std::cout << "[+] Upload concluído! ID: " << analysisId << std::endl;

    checkAnalysisStatus(analysisId);
  }

  return success;
}

void Scanner::checkAnalysisStatus(const std::string &analysisId)
{
    std::string url = "https://www.virustotal.com/api/v3/analyses/" + analysisId;
    std::cout << "[*] Aguardando conclusão da análise..." << std::endl;

    for (int i = 0; i < 5; ++i)
    {
        std::string readBuffer;
        struct curl_slist *headers = NULL;

        CURL *curl = setupCurl(url, readBuffer, headers);
        
        if (curl)
        {
            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK)
            {
                auto json = nlohmann::json::parse(readBuffer);
                std::string status = json["data"]["attributes"]["status"];

                if (status == "completed")
                {
                    std::cout << "[+] Análise finalizada!" << std::endl;
                    auto stats = json["data"]["attributes"]["stats"];
                    
                    std::cout << "\n=== RESULTADO FINAL (APÓS UPLOAD) ===" << std::endl;
                    std::cout << "Maliciosos: " << stats["malicious"] << std::endl;
                    std::cout << "Inofensivos: " << stats["harmless"] << std::endl;
                    std::cout << "=====================================\n" << std::endl;
                    
                    curl_slist_free_all(headers);
                    curl_easy_cleanup(curl);
                    return;
                }
                
                std::cout << "[...] Status: " << status << ". Tentando novamente em 15s..." << std::endl;
            }
            
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }

    std::cout << "[!] O tempo de espera esgotou." << std::endl;
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