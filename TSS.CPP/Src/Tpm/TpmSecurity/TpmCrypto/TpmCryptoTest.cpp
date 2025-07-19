#include "TpmCryptoTest.h"
#include <fstream>
#include <iostream>
#include <string>

void CTpmCryptoTest::SetTpmCrypto(CTpmCryptoRSA* pTpmCrypto)
{
    m_pTpmCrypto = pTpmCrypto;
}

bool CTpmCryptoTest::RunAllTests()
{
    if (!m_pTpmCrypto)
    {
        std::cerr << "CTpmCrypto instance not set!" << std::endl;
        return false;
    }

    bool success = true;

    success &= TestSimpleTypes();
    success &= TestArrayTypes();
    success &= TestStringOperations();
    success &= TestFileOperations();

    TestEncryptDecryptInternal();

    return success;
}

bool CTpmCryptoTest::TestSimpleTypes()
{
    std::cout << "[Test] Simple Types..." << std::endl;
    BYTE bVal = 123, bOut;
    std::vector<BYTE> encrypted;

    if (!m_pTpmCrypto->EncryptByte(bVal, encrypted)) return false;
    if (!m_pTpmCrypto->DecryptByte(encrypted, bOut)) return false;
    return bVal == bOut;
}

bool CTpmCryptoTest::TestArrayTypes()
{
    std::cout << "[Test] Array Types..." << std::endl;
    std::vector<int> intArray = { 1, 2, 3, 4, 5 }, intOut;
    std::vector<BYTE> encrypted;

    if (!m_pTpmCrypto->EncryptIntArray(intArray, encrypted)) return false;
    if (!m_pTpmCrypto->DecryptIntArray(encrypted, intOut)) return false;
    return intArray == intOut;
}

bool CTpmCryptoTest::TestStringOperations()
{
    std::cout << "[Test] String..." << std::endl;
    std::string original = "TPM RSA Test";
    std::string result;
    std::vector<BYTE> encrypted;

    if (!m_pTpmCrypto->EncryptString(original, encrypted)) return false;
    if (!m_pTpmCrypto->DecryptString(encrypted, result)) return false;
    return original == result;
}

bool CTpmCryptoTest::TestFileOperations()
{
    std::cout << "[Test] File Encryption..." << std::endl;

    std::string input = "test_input.txt";
    std::string enc = "test_input.enc";
    std::string output = "test_input.dec";

    // Create dummy input file
    std::ofstream _out(input, std::ios::binary);
    if (!_out)
    {
        std::cerr << "Failed to create input file.\n";
        return false;
    }

    std::string content = "TPM File Encryption Test";
    _out << content;
    _out.close();

    // Encrypt
    if (!m_pTpmCrypto->EncryptFile(input, enc))
    {
        std::cerr << "EncryptFile failed.\n";
        return false;
    }

    // Decrypt
    if (!m_pTpmCrypto->DecryptFile(enc, output))
    {
        std::cerr << "DecryptFile failed.\n";
        return false;
    }

    // Read back both files
    std::ifstream in1(input, std::ios::binary), in2(output, std::ios::binary);
    if (!in1 || !in2)
    {
        std::cerr << "Failed to open input/output file for comparison.\n";
        return false;
    }

    std::string s1((std::istreambuf_iterator<char>(in1)), std::istreambuf_iterator<char>());
    std::string s2((std::istreambuf_iterator<char>(in2)), std::istreambuf_iterator<char>());

    bool match = (s1 == s2);
    if (!match)
        std::cerr << "Decrypted content does not match original.\n";

    return match;
}

bool CTpmCryptoTest::TestEncryptDecryptInternal()
{
    std::cout << "[Test] EncryptDecryptInternal..." << std::endl;

    if (!m_pTpmCrypto)
    {
        std::cerr << "TpmCrypto instance is not set.\n";
        return false;
    }

    // 1. Orijinal veri oluştur
    std::string originalText = "Sample data for internal RSA encryption";    
    std::vector<BYTE> originalData(originalText.begin(), originalText.end());

    std::cout << "\n";
    std::cout << originalText << "\n";

    // 2. Şifrele
    std::vector<BYTE> encryptedData;
    bool encOk = m_pTpmCrypto->EncryptDecryptInternal(originalData, encryptedData, true);
    if (!encOk || encryptedData.empty())
    {
        std::cerr << "EncryptDecryptInternal failed during encryption.\n";
        return false;
    }

    // 3. Decrypt
    std::vector<BYTE> decryptedData;
    bool decOk = m_pTpmCrypto->EncryptDecryptInternal(encryptedData, decryptedData, false);
    if (!decOk || decryptedData.empty())
    {
        std::cerr << "EncryptDecryptInternal failed during decryption.\n";
        return false;
    }

    std::string decryptedText = std::string(decryptedData.begin(), decryptedData.end());

    // 4. Karşılaştır
    bool match = (originalData == decryptedData);
    if (!match)
    {
        std::cerr << "Mismatch between original and decrypted data.\n";
        std::cerr << "Original:  "  << originalText << "\n";
        std::cerr << "Decrypted1: " << decryptedText << "\n";
    }

    return match;
}
