using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FilOverfoerselApp.Services
{
    public interface IAesHandler
    {
        Task<string> FetchAndVerifyPublicKeyAsync();
        Task<string> EncryptAndSendAsync(byte[] fileBytes, string fileName, string publicKeyPem);
    }

    public class AesHandler : IAesHandler
    {
        private readonly HttpClient _http;
        private readonly IConfiguration _config;

        // Pinned fingerprint — beskytter mod man-in-the-middle der erstatter public key
        private static string? _pinnedFingerprint = null;
        private static readonly object _fingerprintLock = new();

        public AesHandler(HttpClient http, IConfiguration config)
        {
            _http = http;
            _config = config;
        }

        public async Task<string> FetchAndVerifyPublicKeyAsync()
        {
            var baseUrl = _config["FilUploadApp:BaseUrl"]
                ?? throw new InvalidOperationException("FilUploadApp:BaseUrl er ikke konfigureret.");

            var response = await _http.GetAsync($"{baseUrl}/api/transfer/public-key");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var data = JsonSerializer.Deserialize<PublicKeyResponse>(json,
                             new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            string pem = data?.PublicKey
                ?? throw new InvalidOperationException("Ingen public key modtaget.");

            string fingerprint = ComputeFingerprint(pem);


            //MITM-beskyttelse via fingerprint pinning
            lock (_fingerprintLock)
            {
                if (_pinnedFingerprint == null)
                    _pinnedFingerprint = fingerprint;
                else if (_pinnedFingerprint != fingerprint)
                    throw new CryptographicException(
                        "ADVARSEL: RSA public key fingerprint matcher ikke den pinnede nøgle. " +
                        "Muligt man-in-the-middle angreb detekteret. Afsendelse afbrudt.");
            }

            return pem;
        }

        public async Task<string> EncryptAndSendAsync(
            byte[] fileBytes, string fileName, string publicKeyPem)
        {
            // Hybrid kryptering: fil krypteres med AES-256-CBC,
            // AES-nøglen krypteres med RSA OAEP-SHA256 (fil er kun i memory)
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.GenerateKey();
            aes.GenerateIV();

            byte[] encryptedFile = EncryptAes(fileBytes, aes.Key, aes.IV);
            byte[] encryptedAesKey = EncryptAesKeyWithRsa(aes.Key, publicKeyPem);

            var payload = new
            {
                encryptedFile = Convert.ToBase64String(encryptedFile),
                encryptedAesKey = Convert.ToBase64String(encryptedAesKey),
                iv = Convert.ToBase64String(aes.IV),
                fileName = fileName,
            };

            var baseUrl = _config["FilUploadApp:BaseUrl"]
                ?? throw new InvalidOperationException("FilUploadApp:BaseUrl er ikke konfigureret.");

            var content = new StringContent(
                JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{baseUrl}/api/transfer/receive", content);

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        private static byte[] EncryptAes(byte[] plainText, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            cs.Write(plainText, 0, plainText.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }


        // Bruger OAEP-SHA256 som er mere sikker end PKCS#1 v1.5 padding (Ikke outdated)
        private static byte[] EncryptAesKeyWithRsa(byte[] aesKey, string publicKeyPem)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem.AsSpan()); 
            return rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256); 
        }

        private static string ComputeFingerprint(string pem)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(pem.Trim());
            byte[] hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLower();
        }

        private class PublicKeyResponse
        {
            public string PublicKey { get; set; } = string.Empty;
        }
    }
}