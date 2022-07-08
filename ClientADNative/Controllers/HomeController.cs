using ClientAD.Models.Native;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ClientAD.Controllers.Native
{

    public class ModelBasic
    {
        public string access_token { get; set; }
        public string refresh_token { get; set; }
    }


    public class GraphModel
    {

        public class GraphUser
        {

            public string displayName { get; set; }
            public string id { get; set; }

        }
        public GraphUser[] value { get; set; }

    }
    public class HomeController : Controller
    {

        private readonly IConfiguration _configuration;
        private readonly string _tenantId;
        private readonly string _clientId;
        private readonly string _client_secret;
        private readonly string _scope;
        private readonly string _scopeAPI;
        public HomeController(IConfiguration config)
        {
            _configuration = config;
            _tenantId = "...";
            _clientId = "...";
            _client_secret = "...";
            _scope = WebUtility.UrlEncode("api://13ae8188-43fa-4da1-86b6-cff6216d624c/backad");
            _scopeAPI = "openid offline_access api://13ae8188-43fa-4da1-86b6-cff6216d624c/backad";


        }
        public async Task<IActionResult> Index()
        {


            var url = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/authorize" + "?" +
                    $"client_id={_clientId}&" +
                    "redirect_uri=https://localhost:44343/home/processCode&" +
                    "response_type=code&" +
                    "scope=" + _scope + "&" +
                    "response_mode=query" + "&" +
                    "state=12345&" +
                    "nonce=xyz";

            return Redirect(url);

        }

        public async Task<IActionResult> processCode(string code)
        {

            //Obter Token Azure AD Autorization Code Flow
            var clientToken = new HttpClient();
            clientToken.DefaultRequestHeaders.Clear();
            var paramsUrl = new Dictionary<string, string>() {

                {"client_id",_clientId},
                {"scope" , _scopeAPI},
                {"redirect_uri" , "https://localhost:44343/home/processCode" },
                {"grant_type" , "authorization_code" },
                {"client_secret" , _client_secret },
                {"code" , code },

            };

            var url = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token";
            var requestrequest = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(paramsUrl)
            };
            var res = clientToken.SendAsync(requestrequest).Result;
            var dataMyApi = res.Content.ReadAsStringAsync().Result;
            var resultMyApi = System.Text.Json.JsonSerializer.Deserialize<ModelBasic>(dataMyApi);




            //Obter Refresh Token Azure AD Autorization Code Flow
            var clientToken2 = new HttpClient();
            var paramsUrl2 = new Dictionary<string, string>() {

                {"client_id",_clientId},
                {"client_secret" , _client_secret },
                {"grant_type" , "refresh_token" },
                {"scope" , "https://graph.microsoft.com/User.Read" },
                {"refresh_token" , resultMyApi.refresh_token},
            };

            var url2 = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token";
            var requestrequest2 = new HttpRequestMessage(HttpMethod.Post, url2)
            {
                Content = new FormUrlEncodedContent(paramsUrl2)
            };
            var res2 = clientToken2.SendAsync(requestrequest2).Result;
            var dataMyApi2 = res2.Content.ReadAsStringAsync().Result;
            var resultMyApi2 = System.Text.Json.JsonSerializer.Deserialize<ModelBasic>(dataMyApi2);



            // Chamada API com token Bearer
            using (HttpClient httpClient = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44316/api/WeatherForecast");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resultMyApi.access_token);
                HttpResponseMessage responseApi = httpClient.SendAsync(request).Result;
                responseApi.EnsureSuccessStatusCode();
                string responseBody = responseApi.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response:");
                Console.WriteLine(responseBody);
            }

            var jwt = new JwtSecurityTokenHandler();
            var canRead = jwt.CanReadToken(resultMyApi.access_token);
            IEnumerable<Claim> claims = default;
            string oid = default;
            if (canRead)
            {
                var tokenRead = jwt.ReadJwtToken(resultMyApi.access_token);
                claims = tokenRead.Claims;
                oid = claims.Where(_ => _.Type == "unique_name").SingleOrDefault().Value;
            }

            //Chamada Graph com token Bearer para user logado
            var resultGraphUser = new GraphModel();
            var urlGraphUser = $"https://graph.microsoft.com/v1.0/users/{oid}";
            //var urlGraphUser = $"https://graph.microsoft.com/v1.0/me";
            using (HttpClient userClient = new HttpClient())
            {
                var requestUser = new HttpRequestMessage(HttpMethod.Get, urlGraphUser);
                requestUser.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resultMyApi2.access_token);

                HttpResponseMessage responseUser = userClient.SendAsync(requestUser).Result;
                responseUser.EnsureSuccessStatusCode();
                var dataGraphUser = responseUser.Content.ReadAsStringAsync().Result;
                resultGraphUser = System.Text.Json.JsonSerializer.Deserialize<GraphModel>(dataGraphUser);

            }


           

            return View();



        }

        public IActionResult Logout()
        {
            var api = new Uri(_configuration["Roles:Api"]);
            var urllogout = $"https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri={api.AbsoluteUri}signin-oidc";
            return Redirect(urllogout);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
