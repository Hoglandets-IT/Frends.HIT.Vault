using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using Newtonsoft.Json;
using System.Text;
using System.Web;

namespace Frends.HIT;


class SecretType {
    [JsonProperty("environment")]
    public string Environment { get; set; }

    [JsonProperty("secretKey")]
    public string SecretKey { get; set; }

    [JsonProperty("secretValue")]
    public string SecretValue { get; set; }

    [JsonProperty("type")]
    public string Type { get; set; }

    [JsonProperty("version")]
    public int Version { get; set; }
}

class SecretResponse {
    [JsonProperty("secret")]
    public SecretType Secret { get; set; }
}


/// <summary>
/// Main class for Vault
/// </summary>
public static class Vault {

    private static string VaultAddr() {
        return Environment.GetEnvironmentVariable("VAULT_ADDR");
    }

    private static string VaultToken() {
        return Environment.GetEnvironmentVariable("VAULT_TOKEN");
    }

    private static string VaultStore() {
        return Environment.GetEnvironmentVariable("VAULT_STORE");
    }

    /// <summary>
    /// Returns a secret from Hashicorp Vault
    /// </summary>
    /// <param name="path">The path to the secret</param>
    /// <returns>Secret string</returns>
    public static string Secret(string path) {   
        var InfisicalAddr = Environment.GetEnvironmentVariable("INFISICAL_ADDR");
        var InfisicalClientId = Environment.GetEnvironmentVariable("INFISICAL_CLIENT_ID");
        var InfisicalClientSecret = Environment.GetEnvironmentVariable("INFISICAL_CLIENT_SECRET");
        var InfisicalProject = Environment.GetEnvironmentVariable("INFISICAL_PROJECT");
        var InfisicalEnvironment = Environment.GetEnvironmentVariable("INFISICAL_ENVIRONMENT");

        var handler = new HttpClientHandler
        {
            ClientCertificateOptions = ClientCertificateOption.Manual,
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };

        var client = new HttpClient(handler);

        var response = client.PostAsync(InfisicalAddr + "/api/v1/auth/universal-auth/login", new StringContent(JsonConvert.SerializeObject(new {
            clientId = InfisicalClientId,
            clientSecret = InfisicalClientSecret
        }), Encoding.UTF8, "application/json")).Result;

        if (!response.IsSuccessStatusCode) {
            throw new Exception("Failed to authenticate to Infisical: " + response.ReasonPhrase);
        }

        var token = JsonConvert.DeserializeObject<Dictionary<string, string>>(response.Content.ReadAsStringAsync().Result)["accessToken"];

        var items = path.Split('/');
        var secret = items[items.Length - 1];
        var secretPath = string.Join('/', items.Take(items.Length - 1));

        if (!secretPath.StartsWith("/")) {
            secretPath = "/" + secretPath;
        }

        if (secretPath.Contains(".")) {
            secretPath = secretPath.Replace(".", "_");
        }

        secretPath = HttpUtility.UrlEncode(secretPath);
        var fullAddr = InfisicalAddr + "/api/v3/secrets/raw/" + secret + "?workspaceId=" + InfisicalProject + "&secretPath=" + secretPath + "&environment=" + InfisicalEnvironment;

        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);

        var request = client.GetAsync(fullAddr).Result;
        if (!request.IsSuccessStatusCode) {
            throw new Exception("Failed to get secret from Infisical: " + request.ReasonPhrase);
        }

        SecretResponse secretResponse = JsonConvert.DeserializeObject<SecretResponse>(request.Content.ReadAsStringAsync().Result);

        return secretResponse.Secret.SecretValue;
    }
    
    
    /// <summary>
    // /// Returns a secret from Hashicorp Vault
    // /// </summary>
    // /// <param name="path">The path to the secret</param>
    // /// <returns>Secret string</returns>
    // public static string Secret(string path) {   
    //     IAuthMethodInfo authMethod = new TokenAuthMethodInfo(VaultToken());
    //     var vaultClientSettings = new VaultClientSettings(VaultAddr(), authMethod);


    //     IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    //     var kv22 = vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path, mountPoint: VaultStore());

    //     Secret<SecretData> kv2Secret = kv22.Result;

    //     if (kv2Secret.Data.Data.Count == 0) {
    //         throw new Exception("Vault secret not found");
    //     }

    //     if (kv2Secret.Data.Data.Count == 1) {
    //         return kv2Secret.Data.Data.First().Value.ToString();
    //     }

    //     var rtnData = new Dictionary<string,string>();

    //     foreach (var x in kv2Secret.Data.Data) {
    //         rtnData[x.Key] = x.Value.ToString();
    //     }

    //     return JsonConvert.SerializeObject(rtnData);
    // }

    /// <summary>
    /// Function to include at the start of a process to enable the usage of the Frends.HIT.Vault.Secret function
    /// </summary>
    public static string EnableSecretFunc(string nothing) {
        return nothing;
    }

    /// <summary>
    /// Returns a function used to retrieve the secret
    /// </summary>
    /// <param name="path">The path to the secret</param>
    /// <returns>function() => string</returns> 
    public static Func<string> GetSecretFunc(string path) {
        return () => Frends.HIT.Vault.Secret(path);
    }
}

