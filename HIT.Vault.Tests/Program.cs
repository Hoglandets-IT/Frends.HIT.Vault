using HIT;

Console.WriteLine(HIT.Vault.Secret("SMB/HVFS01/f-freekonomiint02"));
var secret = HIT.Vault.GetSecretFunc("SMB/HVFS01");
Console.WriteLine(secret());