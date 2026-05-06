#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

class Scanner
{
public:
  explicit Scanner(const std::string &apiKey);

  void processFile(const std::string &filePath);

private:
  std::string apiKey;

  std::string calculateSHA256(const std::string &filePath);

  nlohmann::json getReport(const std::string &hash);

  bool uploadFile(const std::string &filePath);

  void displayResult(const nlohmann::json &report);

  CURL* setupCurl(const std::string &url, std::string &responseBuffer, struct curl_slist* &headers);
};

#endif