#include <iostream>
#include "Scanner.hpp"

int main(int argc, char *argv[])
{
  std::cout << "--- VirusTotal Scanner CLI ---" << std::endl;

  if (argc < 2)
  {
    std::cout << "Uso: ./vt_scanner <arquivo>" << std::endl;
    return 1;
  }

  Scanner scanner("minha_chave_temporaria");
  scanner.processFile(argv[1]);

  return 0;
}