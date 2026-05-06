#include <iostream>
#include "Scanner.hpp"

int main(int argc, char* argv[])
{
    std::cout << "--- VirusTotal Scanner CLI ---" << std::endl;
    
    if (argc < 2) 
    {
        std::cout << "Uso: ./vt_scanner <caminho_do_arquivo>" << std::endl;
        return 1;
    }

    std::cout << "Arquivo selecionado: " << argv[1] << std::endl;

    return 0;
}