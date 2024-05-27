using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using Newtonsoft.Json;
using System.ComponentModel;


namespace HIT;

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
        IAuthMethodInfo authMethod = new TokenAuthMethodInfo(VaultToken());
        var vaultClientSettings = new VaultClientSettings(VaultAddr(), authMethod);


        IVaultClient vaultClient = new VaultClient(vaultClientSettings);

        var kv22 = vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path, mountPoint: VaultStore());

        Secret<SecretData> kv2Secret = kv22.Result;

        if (kv2Secret.Data.Data.Count == 0) {
            throw new Exception("Vault secret not found");
        }

        if (kv2Secret.Data.Data.Count == 1) {
            return kv2Secret.Data.Data.First().Value.ToString();
        }

        var rtnData = new Dictionary<string,string>();

        foreach (var x in kv2Secret.Data.Data) {
            rtnData[x.Key] = x.Value.ToString();
        }

        return JsonConvert.SerializeObject(rtnData);
    }

    /// <summary>
    /// Function to include at the start of a process to enable the usage of the HIT.Vault.Secret function
    /// </summary>
    public static void EnableSecretFunc() {
        return;
    }

    /// <summary>
    /// Returns a function used to retrieve the secret
    /// </summary>
    /// <param name="path">The path to the secret</param>
    /// <returns>function() => string</returns> 
    public static Func<string> GetSecretFunc(string path) {
        return () => Secret(path);
    }
}

