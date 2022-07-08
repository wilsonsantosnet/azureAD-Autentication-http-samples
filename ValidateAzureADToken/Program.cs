using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ValidateAzureADToken
{
    public class AzureTokenHeader
    {


    }
    public class PayLoad {
        public List<string> Roles { get; set; }
    }
    public class Key
    {


        public string kty { get; set; }
        public string use { get; set; }
        public string kid { get; set; }
        public string x5t { get; set; }
        public string n { get; set; }
        public string e { get; set; }
        public string[] x5c { get; set; }


    }
    public class MicrosoftConfigurationKeys
    {


        public IEnumerable<Key> keys { get; set; }

    }

    /// <summary>
    /// https://stackoverflow.com/questions/39866513/how-to-validate-azure-ad-security-token
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Validando Token!");

            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiJhcGk6Ly8xM2FlODE4OC00M2ZhLTRkYTEtODZiNi1jZmY2MjE2ZDYyNGMiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83NmEwZTY0ZC00NGZlLTRiMTAtODVmMy00MjRmYjkxODY4ZGQvIiwiaWF0IjoxNjU0NjI5NTQ0LCJuYmYiOjE2NTQ2Mjk1NDQsImV4cCI6MTY1NDYzNDQwMCwiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhUQUFBQUx0cGp2ZUVCWFpqOVlVUG9seGJFa2NzbWZUSGxzZU5TM2F0T0h0U2VGRWNNd1NFRkk5a0F1SENTTlR1QTUvRWwiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMWNlOWZiMWUtODM1ZC00MDIwLWE1YWUtMDQ2OTVmZGQ1ZTM0IiwiYXBwaWRhY3IiOiIxIiwiZmFtaWx5X25hbWUiOiIwMSIsImdpdmVuX25hbWUiOiJ1c3VhcmlvMDEiLCJpcGFkZHIiOiIxODYuMjA3Ljc3Ljg2IiwibmFtZSI6InVzdWFyaW8wMSIsIm9pZCI6Ijg5MjA2YWIzLWE0OTUtNDViNC1hMDIzLWJiOWZkZjQ5M2Y1YyIsInJoIjoiMC5BWDBBVGVhZ2R2NUVFRXVGODBKUHVSaG8zWWlCcmhQNlE2Rk5ocmJQOWlGdFlreWFBQVkuIiwicm9sZXMiOlsiQ29udHJpYnV0b3IiXSwic2NwIjoiYmFja2FkIiwic3ViIjoiVFNYc2NoOENIWkNJUUIyX0U2QnlVLTdKWEMwQ25TMkhERFN4Q3V4ei1zbyIsInRpZCI6Ijc2YTBlNjRkLTQ0ZmUtNGIxMC04NWYzLTQyNGZiOTE4NjhkZCIsInVuaXF1ZV9uYW1lIjoidXN1YXJpbzAxQHRkY3BvY2F6dXJlYWQub25taWNyb3NvZnQuY29tIiwidXBuIjoidXN1YXJpbzAxQHRkY3BvY2F6dXJlYWQub25taWNyb3NvZnQuY29tIiwidXRpIjoiRDZuVzlrX1l3RUtnMk9jZGppdVZBQSIsInZlciI6IjEuMCJ9.sLTm54cGGdyOrPOYAJIeO99pkkn_XXszjOhpIHj5lW52tC-w__SfXhJimqjJamogQqn2i55MCXid2PjdVcR6AXLiyWHnn7v6IBZ5MVd-TA_B1HFoNPDH6zyRGhfoWcweVlRdVxuzfRCsZwUgx3WXXp5MwQpi21sAEfSb-eWBE4S4y_xUwZEIyF-59jrwymS9xTLRnlygN3RpT8TZo0lX1cr-4ANlcAL8OuNYI3BBIfM0jkh5hV9JWrwEhPwunHqtkKIZTQ-IJSYPj19aQJ8tfIYPo4IkAgoSaMCTT-p3wvWTHVdE8A5E-aoA1LpxRth-O-_2L9Y2r3Y7u-icr-dDJg";

          
            //Testar carregando as configurações usando o openId Configuration
            var isValid1 = ValidateTokenWithIdentityModelAndOpenIdConfig(token, "api://3dbc5a70-246a-4f03-ac06-ea1a501dcc48");


            //Pegar a chave pelo KID
            var allParts = token.Split(".");
            var header = allParts[0];
            var payload = allParts[1];
            var signature = allParts[2];

            var kid = ReadKid(header);
            var roles = ReadRoles(payload);


            //Processo todo manual
            var isValid4 = ValidateToken(kid, header, payload, signature);


            Console.WriteLine("Validação Token terminada!");

        }

        private static string ReadKid(string header)
        {

            //var uncodeBase64 = DecodeFrom64(header);
            var uncodeBase64 = Base64UrlEncoder.Decode(header);

            var azureKeys = Newtonsoft.Json.JsonConvert.DeserializeObject<Key>(uncodeBase64);
            return azureKeys.kid;
            

        }

        private static List<string> ReadRoles(string payload)
        {
            var uncodeBase64 = Base64UrlEncoder.Decode(payload);
            var azureKeys = Newtonsoft.Json.JsonConvert.DeserializeObject<PayLoad>(uncodeBase64);
            return azureKeys.Roles;
        }

        private static string DecodeFrom64(string encodedData)

        {
            var encodedDataAsBytes = Convert.FromBase64String(encodedData);
            return ASCIIEncoding.ASCII.GetString(encodedDataAsBytes);

        }

        public static bool ValidateTokenWithIdentityModelAndOpenIdConfig(string token,  string myAudience)
        {
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>($"https://sts.windows.net/779811d8-4753-4c34-baeb-6b53957d52e3/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            var openidconfig = configManager.GetConfigurationAsync().Result;
            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = openidconfig.Issuer,
                    IssuerSigningKeys = openidconfig.SigningKeys,
                    ValidAudience = myAudience
                }, out SecurityToken validatedToken);
                
                return true;

            }
            catch (Exception ex)
            {
                return false;
            }
            
        }

        public static bool ValidateTokenWithIdentityModel(string token,string kid, string mySecret, string myIssuer,string myAudience)
        {

            //var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret)) { KeyId = kid };
            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = myIssuer,
                    IssuerSigningKey = key,
                    ValidAudience = myAudience
                }, out SecurityToken validatedToken);
            }
            catch (Exception ex)
            {
                return false;
            }
            return true;

        }

       
        private static bool ValidateToken(string kid, string header, string payload, string signature)
        {
            string keysAsString = null;
            const string microsoftKeysUrl = "https://login.microsoftonline.com/common/discovery/keys";
            //const string microsoftKeysUrl = "https://login.microsoftonline.com/779811d8-4753-4c34-baeb-6b53957d52e3/discovery/keys";

            using (var client = new HttpClient())
            {
                keysAsString = client.GetStringAsync(microsoftKeysUrl).Result;
            }
            var azureKeys = Newtonsoft.Json.JsonConvert.DeserializeObject<MicrosoftConfigurationKeys>(keysAsString);
            var signatureKeyIdentifier = azureKeys.keys.FirstOrDefault(key => key.kid.Equals(kid));
            if (signatureKeyIdentifier != null)
            {
                var signatureKey = signatureKeyIdentifier.x5c.First();
                var certificate = new X509Certificate2(Convert.FromBase64String(signatureKey));
                var rsa = certificate.GetRSAPublicKey();
                var data = Encoding.ASCII.GetBytes(string.Format("{0}.{1}", header, payload));

                var signatureBytes = Base64UrlEncoder.DecodeBytes(signature);
                var isValidSignature = rsa.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return isValidSignature;
            }

            return false;
        }


        public static string ReadKidWithIdentityModel(string txtJwtIn)
        {

            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtInput = txtJwtIn;
            var readableToken = jwtHandler.CanReadToken(jwtInput);

            if (readableToken != true)
            {
                throw new InvalidOperationException("The token doesn't seem to be in a proper JWT format.");
            }

            var token = jwtHandler.ReadJwtToken(jwtInput);
            return token.Header.Kid;



        }

        private static string GetKey(string kid)
        {

            string keysAsString = null;
            const string microsoftKeysUrl = "https://login.microsoftonline.com/common/discovery/keys";

            using (var client = new HttpClient())
            {
                keysAsString = client.GetStringAsync(microsoftKeysUrl).Result;
            }
            var azureKeys = Newtonsoft.Json.JsonConvert.DeserializeObject<MicrosoftConfigurationKeys>(keysAsString);
            var signatureKeyIdentifier = azureKeys.keys.FirstOrDefault(key => key.kid.Equals(kid));
            if (signatureKeyIdentifier != null)

                return signatureKeyIdentifier.x5c.First();

            return "";

        }

        private static IEnumerable<string> GetKeys()
        {

            string keysAsString = null;
            const string microsoftKeysUrl = "https://login.microsoftonline.com/common/discovery/keys";

            using (var client = new HttpClient())
            {
                keysAsString = client.GetStringAsync(microsoftKeysUrl).Result;
            }
            var azureKeys = Newtonsoft.Json.JsonConvert.DeserializeObject<MicrosoftConfigurationKeys>(keysAsString);

            return azureKeys.keys.Select(_ => _.x5c[0]);

        }


    }
}
