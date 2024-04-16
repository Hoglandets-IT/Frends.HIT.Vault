// using Vault;
// using Vault.Client;
// using Vault.Model;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using Newtonsoft.Json;
using System.Text.Json;


namespace Frends.HIT;

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
        






        // VaultConfiguration config = new VaultConfiguration(VaultAddr());
        // VaultClient client = new VaultClient(config);
        // client.SetToken(VaultToken());

        // VaultResponse<KvV2ReadResponse> resp = client.Secrets.KvV2Read(path, VaultStore());

        // if (resp == null) {
        //     throw new Exception("Vault secret not found");
        // }

        // if (resp.Data == null) {
        //     throw new Exception("Vault secret not found");
        // }

        // var respData = (Newtonsoft.Json.Linq.JObject)resp.Data.Data;
        
        // if (respData.Count == 0) {
        //     throw new Exception("Vault secret not found");
        // }

        // if (respData.Count == 1) {
        //     return respData.First.First.ToString();
        // }

        // return respData.ToString();
    }
}

