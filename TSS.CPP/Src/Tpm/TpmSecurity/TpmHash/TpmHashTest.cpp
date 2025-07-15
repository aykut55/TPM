#include "TpmHashTest.h"
#include <iostream>
#include <fstream>

void CTpmHashTest::SetTpmHash(CTpmHash* hashObj)
{
    m_hash = hashObj;
}

bool CTpmHashTest::RunAllTests()
{
    if (!m_hash)
    {
        std::cerr << "[CTpmHashTest] Hash object not set.\n";
        return false;
    }

    bool success = true;
    success &= TestHashString();
    success &= TestHashData();
    success &= TestHashFile("example.txt"); // Örnek dosya adı

    return success;
}

bool CTpmHashTest::TestHashString()
{
    std::string data = "Hello, TPM!";
    std::vector<BYTE> hashResult;

    if (!m_hash->HashString(TPM_ALG_ID::SHA256, data, hashResult))
    {
        std::cerr << "[TestHashString] Failed.\n";
        return false;
    }

    std::cout << "HashString (SHA256): " << m_hash->EncodeHex(hashResult) << "\n";
    return true;
}

bool CTpmHashTest::TestHashData()
{
    std::vector<BYTE> input = { 0x10, 0x20, 0x30, 0x40 };
    std::vector<BYTE> hash;

    if (!m_hash->HashData(TPM_ALG_ID::SHA1, input, hash))
    {
        std::cerr << "[TestHashData] Failed.\n";
        return false;
    }

    std::cout << "HashData (SHA1): " << m_hash->EncodeHex(hash) << "\n";
    return true;
}

#include <iomanip> // std::setw
bool CTpmHashTest::TestHashFile(const std::string& filePath)
{
    std::vector<BYTE> hash;

    // Callback: ilerleme durumunu konsola yazdır
    auto progressCallback = [](size_t bytesProcessed, size_t bytesTotal)
        {
            double progress = 100.0 * bytesProcessed / (bytesTotal ? bytesTotal : 1);
            std::cout << "\rProgress: " << static_cast<int>(progress) << "% completed" << std::flush;
            std::cout << std::flush;
        };

    if (!m_hash->HashFileChunked(TPM_ALG_ID::SHA256, filePath, hash, 1024, progressCallback))
    {
        std::cerr << "\n[TestHashFile] Failed for file: " << filePath << "\n";
        return false;
    }

    std::cout << "\nHashFile SHA256 result: " << m_hash->EncodeHex(hash) << "\n";
    return true;
}
