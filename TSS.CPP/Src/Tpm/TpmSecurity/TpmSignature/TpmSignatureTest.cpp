#include "TpmSignatureTest.h"
#include <iostream>

void CTpmSignatureTest::SetTpmSignature(CTpmSignature* pSignature)
{
    m_signature = pSignature;
}

bool CTpmSignatureTest::RunAllTests()
{
    if (!m_signature)
    {
        std::cerr << "[CTpmSignatureTest] No signature object set.\n";
        return false;
    }

    std::vector<BYTE> testData = { 'T', 'P', 'M', '_', 'S', 'I', 'G', 'N' };

    std::vector<BYTE> signatureOut;
    if (!m_signature->SignData(testData, signatureOut))
    {
        std::cerr << "[CTpmSignatureTest] Sign() failed.\n";
        return false;
    }

    std::cout << "[CTpmSignatureTest] Sign() succeeded.\n";
    std::cout << "Signature size: " << signatureOut.size() << " bytes\n";
    std::cout << "Signature (Hex): " << m_signature->EncodeHex(signatureOut) << "\n";
    std::cout << "Signature (Base64): " << m_signature->EncodeBase64(signatureOut) << "\n";

    if (!m_signature->VerifySignature(testData, signatureOut))
    {
        std::cerr << "[CTpmSignatureTest] VerifySignature() failed.\n";
        return false;
    }

    std::cout << "[CTpmSignatureTest] VerifySignature() succeeded.\n";



    std::vector<BYTE> modulus;
    UINT32 exponent = 0;

    if (m_signature->ExportPublicKeyRaw(modulus, exponent))
    {
        std::cout << "Modulus size: " << modulus.size() << " bytes\n";
        std::cout << "Exponent: " << exponent << "\n";

        std::cout << "Modulus (Hex): ";
        for (BYTE b : modulus) std::cout << std::hex << (int)b;
        std::cout << "\n";
    }

    std::string pem;
    if (m_signature->ConvertRsaPublicKeyToPem(modulus, exponent, pem))
        std::cout << pem;

/*
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApUeA1XhWD+T+jhk7td5O
OHEzx8Dk2rA++V0+L4o4Zh0y9FVzrcvF63gnVugpBR9m51n9kVmN9P53QZ1XQJrw
L0f7cXyFyRTHrhBtRhULVTRKSlBS7zH2T3hrDtQxAMpr1hKtNRzGw4ZcEk1KAwzM
XaztE2q0I7CrHnnzQZwNJo6PZQIDAQAB
-----END PUBLIC KEY-----
*/

    return true;
}

std::vector<BYTE> DummyAESEncrypt(const std::string& message)
{
    std::vector<BYTE> encrypted(message.begin(), message.end());
    // Gerçek AES şifreleme yerine sadece içeriği ters çeviriyoruz
    std::reverse(encrypted.begin(), encrypted.end());
    return encrypted;
}

std::string DummyEncodeHex(const std::vector<BYTE>& data)
{
    std::ostringstream oss;
    for (BYTE b : data)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}


bool CTpmSignatureTest::TestMesajSign(const std::string& rawMessage)
{
    if (!m_signature)
    {
        std::cerr << "[CTpmSignatureTest] No signature object set.\n";
        return false;
    }

    // 1. Mesajı ekrana yaz
    std::cout << "[TestMesajSign] Raw message: " << rawMessage << "\n";

    // 2. AES ile şifrele (dummy fonksiyonla simüle ediyoruz)
    std::vector<BYTE> encryptedData = DummyAESEncrypt(rawMessage);

    // 3. Hex encode et
    std::string encodedHex = DummyEncodeHex(encryptedData);
    std::cout << "[TestMesajSign] Hex encoded AES data: " << encodedHex << "\n";

    // 4. Sign işlemi
    std::vector<BYTE> signature;
    if (!m_signature->SignData(std::vector<BYTE>(encodedHex.begin(), encodedHex.end()), signature))
    {
        std::cerr << "[TestMesajSign] SignData failed.\n";
        return false;
    }

    std::cout << "[TestMesajSign] Signature size: " << signature.size() << "\n";
    std::cout << "[TestMesajSign] Signature (Hex): " << DummyEncodeHex(signature) << "\n";

    // 5. Public key'i export et (modulus + exponent)
    std::vector<BYTE> modulus;
    UINT32 exponent;
    if (!m_signature->ExportPublicKeyRaw(modulus, exponent))
    {
        std::cerr << "[TestMesajSign] ExportPublicKeyRaw failed.\n";
        return false;
    }

    std::string pem;
    if (!m_signature->ConvertRsaPublicKeyToPem(modulus, exponent, pem))
    {
        std::cerr << "[TestMesajSign] ConvertRsaPublicKeyToPem failed.\n";
        return false;
    }

    std::cout << "[TestMesajSign] Public Key PEM:\n" << pem << "\n";

    // 6.

    TestMesajVerify(encodedHex, signature);

    return true;
}

bool CTpmSignatureTest::TestMesajVerify(const std::string& hexEncodedData, const std::vector<BYTE>& signature)
{
    if (!m_signature)
    {
        std::cerr << "[CTpmSignatureTest] No signature object set.\n";
        return false;
    }

    try
    {
        // Hex'i byte dizisine çevir (Decode)
        std::vector<BYTE> decodedData;
        for (size_t i = 0; i < hexEncodedData.size(); i += 2)
        {
            std::string byteString = hexEncodedData.substr(i, 2);
            BYTE b = static_cast<BYTE>(std::stoi(byteString, nullptr, 16));
            decodedData.push_back(b);
        }

        // İmzayı doğrula
        bool result = m_signature->VerifySignature(decodedData, signature);
        if (result)
            std::cout << "[TestMesajVerify] Signature verification succeeded.\n";
        else
            std::cerr << "[TestMesajVerify] Signature verification FAILED.\n";

        return result;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[TestMesajVerify] Exception: " << ex.what() << "\n";
        return false;
    }
}



/*
1. Veriyi oluşturuyorsun
std::string payload = "2025-07-18 22:15:43 Aykut.T";

2. AES ile şifreliyorsun
std::vector<BYTE> aesEncrypted = AES_Encrypt(payload);

3. Hex’e encode ediyorsun (isteğe bağlı ama taşımayı kolaylaştırır)
std::string encodedHex = HexEncode(aesEncrypted);

4. Hex string’i RSA ile imzalıyorsun
std::vector<BYTE> signature;
m_signature->SignData(encodedHex, signature);

5. Public Key PEM formatına çeviriyorsun
std::vector<BYTE> modulus;
UINT32 exponent;
m_signature->ExportPublicKeyRaw(modulus, exponent);
std::string pem;
m_signature->ConvertRsaPublicKeyToPem(modulus, exponent, pem);




Şunları gönderiyorsun:
encodedHex	Hex string (AES çıkışı)	Doğrulamak için imzalanan veri
signature	std::vector<BYTE>	RSA imza verisi
public.pem	PEM string veya dosyası	RSA public key




Karşı Taraf Ne Yapacak?
1. PEM dosyasını RSA public key olarak yükler
RSA* rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);

2. encodedHex + signature ile doğrulama yapar
bool isValid = RSA_verify(..., encodedHex, ..., signature, ..., rsa);
Eğer doğrulama başarılıysa, mesaj gerçekten senin tarafından oluşturulmuştur ve değiştirilmemiştir.



ParseRsaPublicKeyFromPem(...) → PEM string → modulus, exponent

VerifySignatureWithRawPublicKey(...) → Verilen modulus, exponent ile data ve signature doğrulama

*/

bool CTpmSignatureTest::TestHmacSignOnly()
{
    if (!m_signature)
    {
        std::cerr << "[CTpmSignatureTest] No signature object set.\n";
        return false;
    }

    std::cout << "[CTpmSignatureTest] Starting HMAC Sign test...\n";

    std::vector<BYTE> testData = { 'T', 'P', 'M', '_', 'H', 'M', 'A', 'C' };
    std::vector<BYTE> signature;

    if (!m_signature->SignData(testData, signature))
    {
        std::cerr << "[CTpmSignatureTest] HMAC SignData failed.\n";
        return false;
    }

    std::cout << "[CTpmSignatureTest] HMAC Signature (hex): ";
    for (auto b : signature)
        printf("%02X", b);
    std::cout << "\n";

    std::cout << "[CTpmSignatureTest] TPM generated HMAC signature.\n";
    std::cout << "[CTpmSignatureTest] NOTE: TPM does not support internal HMAC verification.\n";

    if (!m_signature->VerifySignature(testData, signature))
    {
        std::cerr << "[CTpmSignatureTest] HMAC VerifySignature failed.\n";
        return false;
    }

    std::cout << "[CTpmSignatureTest] HMAC VerifySignature succeeded.\n";
    return true;
}