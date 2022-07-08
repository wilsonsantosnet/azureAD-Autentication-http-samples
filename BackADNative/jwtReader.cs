using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Text;
using System.Security;

namespace BackAD
{
    public class AzureActiveDirectoryToken
    {
        public string access_token { get; set; }

    }
    public class Key
    {


        public string kty { get; set; }
        public string use { get; set; }
        public string kid { get; set; }
        public string x5t { get; set; }
        public string n { get; set; }
        public string e { get; set; }
        public string x5c { get; set; }


    }
    public class MicrosoftConfigurationKeys
    {


        public IEnumerable<Key> keys { get; set; }

    }

    public class Token
    {

    }
    public class jwtReader
    {

        public string Read(string txtJwtIn)
        {


            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtInput = txtJwtIn;
            var JwtOut = "";

            //Check if readable token (string is in a JWT format)
            var readableToken = jwtHandler.CanReadToken(jwtInput);

            if (readableToken != true)
            {
                return "The token doesn't seem to be in a proper JWT format.";
            }

            if (readableToken == true)
            {
                var token = jwtHandler.ReadJwtToken(jwtInput);

                //Extract the headers of the JWT
                var headers = token.Header;
                var jwtHeader = "{";

                foreach (var h in headers)
                {
                    jwtHeader += '"' + h.Key + "\":\"" + h.Value + "\",";
                }

                jwtHeader += "}";
                JwtOut = "Header:\r\n" + JToken.Parse(jwtHeader).ToString(Formatting.Indented);

                //Extract the payload of the JWT
                var claims = token.Claims;
                var jwtPayload = "{";
                foreach (Claim c in claims)
                {
                    jwtPayload += '"' + c.Type + "\":\"" + c.Value + "\",";
                }
                jwtPayload += "}";
                JwtOut += "\r\nPayload:\r\n" + JToken.Parse(jwtPayload).ToString(Formatting.Indented);
            }

            return JwtOut;

        }

        internal async Task<bool> ValidateToken(string clearToken)
        {


            var allParts = clearToken.Split(".");
            var header = allParts[0];
            var payload = allParts[1];
            var signature = allParts[2];
            //var accessTokenHeader = header.ToBytesFromBase64URLString().ToAscii().FromJsonString<AzureTokenHeader>();

            //var isValid = await ValidateToken(accessTokenHeader.kid, header, payload, signature);
            //if (!isValid)
            //{
            //    throw new SecurityException("Token can not be validated");
            //}

            throw new NotImplementedException();
        }

        public async Task<bool> ValidateToken(string kid, string header, string payload, string signature)
        {
            string keysAsString = null;
            const string microsoftKeysUrl = "https://login.microsoftonline.com/common/discovery/keys";

            using (var client = new HttpClient())
            {
                keysAsString = await client.GetStringAsync(microsoftKeysUrl);
            }
            var azureKeys = Newtonsoft.Json.JsonConvert.DeserializeObject<MicrosoftConfigurationKeys>(keysAsString);
            var signatureKeyIdentifier = azureKeys.keys.FirstOrDefault(key => key.kid.Equals(kid));
            if (signatureKeyIdentifier != null)
            {
                var signatureKey = signatureKeyIdentifier.x5c;
                var certificate = new X509Certificate2(Convert.FromBase64String(signatureKey));
                var rsa = certificate.GetRSAPublicKey();
                var data = Encoding.ASCII.GetBytes(string.Format("{0}.{1}", header, payload));
                var isValidSignature = rsa.VerifyData(data, Convert.FromBase64String(signatureKey), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return isValidSignature;
            }

            return false;
        }


    }
}
