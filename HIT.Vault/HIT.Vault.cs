using Vault;
using Vault.Client;
using Vault.Model;

namespace HIT;

// / <summary>
// / Main class for Vault
// / </summary>
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
        VaultConfiguration config = new VaultConfiguration(VaultAddr());
        VaultClient client = new VaultClient(config);
        client.SetToken(VaultToken());

        VaultResponse<KvV2ReadResponse> resp = client.Secrets.KvV2Read(path, VaultStore());

        if (resp == null) {
            throw new Exception("Vault secret not found");
        }

        if (resp.Data == null) {
            throw new Exception("Vault secret not found");
        }

        var respData = (Newtonsoft.Json.Linq.JObject)resp.Data.Data;
        
        if (respData.Count == 0) {
            throw new Exception("Vault secret not found");
        }

        if (respData.Count == 1) {
            return respData.First.First.ToString();
        }

        return respData.ToString();
    }
}

