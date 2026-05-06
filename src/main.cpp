#include <iostream>
#include "Scanner.hpp"
#include "Utils.hpp"

int main(int argc, char *argv[])
{
  std::cout << "--- VirusTotal Scanner CLI ---" << std::endl;

  if (argc < 2)
  {
    std::cout << "Uso: ./vt_scanner <arquivo>" << std::endl;
    return 1;
  }

  auto env = Utils::loadEnv(".env");
  std::string apiKey = env["VT_API_KEY"];

  if (apiKey.empty())
  {
    std::cerr << "[-] Erro: VT_API_KEY não encontrada no arquivo .env" << std::endl;
    return 1;
  }

  Scanner scanner(apiKey);
  scanner.processFile(argv[1]);

  return 0;
}