#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <map>

class Utils
{
public:
  static std::map<std::string, std::string> loadEnv(const std::string &filePath);
};

#endif