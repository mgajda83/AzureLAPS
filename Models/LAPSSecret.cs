using System;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace LAPSPortal.Models
{
    public class LAPSSecret
    {
        // Declare LAPSSecret class attributes
        public string SecretDeviceName { get; set; }
        public string SecretValue { get; set; }
        public string SecretDate { get; set; }
        public string SecretId { get; set; }
        public string SecretUserName { get; set; }

        public static async Task<LAPSSecret> GetComputerAsync(string keyVaultUri, string searchValue)
        {
            // Assign empty string to LAPSSecret attrinbutes
            string SecretDeviceName = string.Empty;
            string secretValue = string.Empty;
            string secretDate = string.Empty;
            string secretId = string.Empty;
            string secretUserName = string.Empty;

            // Construct KeyVault Secret client
            var keyVaultClient = new SecretClient(vaultUri: new Uri(keyVaultUri), credential: new DefaultAzureCredential());

            // Search for secret with computer name in Key Vault
            var secretOperation = await keyVaultClient.GetSecretAsync(searchValue);
            var secret = secretOperation.Value;

            try
            {
                SecretDeviceName = secret.Name;
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretValue = secret.Value;
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretDate = secret.Properties.UpdatedOn.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretId = secret.Properties.Id.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretUserName = secret.Properties.Tags["UserName"]?.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            LAPSSecret keyVaultItem = new LAPSSecret()
            {
                SecretDeviceName = SecretDeviceName,
                SecretValue = secretValue,
                SecretDate = secretDate,
                SecretId = secretId,
                SecretUserName = secretUserName
            };

            return keyVaultItem;
        }
    }
}
