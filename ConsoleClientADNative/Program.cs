using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;

namespace ConsoleClientAD.Native
{
    public class ModelBasic
    {
        public string access_token { get; set; }
    }
    class Program
    {
        static void Main(string[] args)
        {
            //Obter Token Azure AD Client Credencial
            var clientToken = new HttpClient();
            var paramsUrl = new Dictionary<string, string>() {

                {"client_id","..."},
                {"client_secret" , "..." },
                {"grant_type" , "client_credentials" },
                {"scope" , "api://3dbc5a70-246a-4f03-ac06-ea1a501dcc48/.default" }
            };

            var url = "https://login.microsoftonline.com/779811d8-4753-4c34-baeb-6b53957d52e3/oauth2/v2.0/token";
            var requestrequest = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(paramsUrl)
            };
            var res = clientToken.SendAsync(requestrequest).Result;
            var data = res.Content.ReadAsStringAsync().Result;
            var result = System.Text.Json.JsonSerializer.Deserialize<ModelBasic>(data);

            // Chamada API com token Bearer
            using (HttpClient httpClient = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44316/api/WeatherForecast");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.access_token);
                HttpResponseMessage responseApi = httpClient.SendAsync(request).Result;
                responseApi.EnsureSuccessStatusCode();
                string responseBody = responseApi.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response:");
                Console.WriteLine(responseBody);
            }


            Console.WriteLine("Hello World!");
        }
    }
}
