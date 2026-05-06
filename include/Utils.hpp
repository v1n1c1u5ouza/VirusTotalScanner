#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <map>

class Utils
{
public:
  static std::map<std::string, std::string> loadEnv(const std::string &filePath);

  static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
};

#endif