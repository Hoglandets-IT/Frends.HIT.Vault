using Frends.HIT;

Console.WriteLine(Frends.HIT.Vault.Secret("SMB/HVFS01/f-freekonomiint02"));
var secret = Frends.HIT.Vault.GetSecretFunc("SMB/HVFS01");
Console.WriteLine(secret());