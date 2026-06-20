using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FilOverfoerselApp.Services
{
    public interface IAesGcmHandler
    {
        Task<string> EncryptAndSendAsync(byte[] fileBytes, string fileName, string publicKeyPem);
    }

    public class AesGcmHandler : IAesGcmHandler
    {
        private readonly HttpClient _http;
        private readonly IConfiguration _config;

        
        private const int NonceSize = 12; 
        private const int TagSize   = 16; 

        public AesGcmHandler(HttpClient http, IConfiguration config)
        {
            _http   = http;
            _config = config;
        }

        public async Task<string> EncryptAndSendAsync(
            byte[] fileBytes, string fileName, string publicKeyPem)
        {
            
            byte[] aesKey = RandomNumberGenerator.GetBytes(32); 
            byte[] nonce  = RandomNumberGenerator.GetBytes(NonceSize);

            
            byte[] cipherText = new byte[fileBytes.Length];
            byte[] tag        = new byte[TagSize];

            using (var gcm = new AesGcm(aesKey, TagSize))
                gcm.Encrypt(nonce, fileBytes, cipherText, tag);

            
            byte[] encryptedAesKey = EncryptKeyWithRsa(aesKey, publicKeyPem);

            
            var payload = new
            {
                encryptedFile   = Convert.ToBase64String(cipherText),
                encryptedAesKey = Convert.ToBase64String(encryptedAesKey),
                nonce           = Convert.ToBase64String(nonce),
                tag             = Convert.ToBase64String(tag),
                fileName        = fileName,
            };

            var baseUrl = _config["FilUploadApp:BaseUrl"]
                ?? throw new InvalidOperationException("FilUploadApp:BaseUrl er ikke konfigureret.");

            var content  = new StringContent(
                JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{baseUrl}/api/transfer/receive-gcm", content);

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        private static byte[] EncryptKeyWithRsa(byte[] key, string publicKeyPem)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem.AsSpan()); 
            return rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
        }
    }
}
