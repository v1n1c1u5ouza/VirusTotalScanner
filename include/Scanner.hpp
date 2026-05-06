#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
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
};

#endif