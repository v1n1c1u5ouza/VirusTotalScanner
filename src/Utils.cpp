#include <Utils.hpp>
#include <fstream> 
#include <sstream>

std::map<std::string, std::string> Utils::loadEnv(const std::string &filePath)
{
  std::map<std::string, std::string> envVars;
  std::ifstream file(filePath);

  if (!file.is_open())
  {
    return envVars;
  }
  
  std::string line;
  while (std::getline(file, line))
  {
    if (line.empty() || line[0] == '#') continue;

    std::size_t delimeterPos = line.find('=');
    if (delimeterPos != std::string::npos)
    {
      std::string key = line.substr(0, delimeterPos);
      std::string value = line.substr(delimeterPos + 1);
      envVars[key] = value;
    }
  }

  return envVars;
}

size_t Utils::WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
 ((std::string *)userp) ->append((char *)contents, size * nmemb);
 return size * nmemb;  
}
