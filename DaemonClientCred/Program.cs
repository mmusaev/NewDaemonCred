using Microsoft.Identity.Client;
using System;
using System.Configuration;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DaemonClientCred
{
    class Program
    {
        private static readonly string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static readonly string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static readonly string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string certName = ConfigurationManager.AppSettings["ida:CertName"];
        private static readonly string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly string audienceUri = ConfigurationManager.AppSettings["ida:AudienceUri"];
        private static readonly string funcAppUrl = ConfigurationManager.AppSettings["ida:FunctionUrl"];

        static async Task Main(string[] args)
        {
            try
            {
                var result = await CallAPI();
                Console.WriteLine($"Here is the result {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.ReadKey();
        }

        static async Task<string> CallAPI()
        {
            var result = await GetAccessTokenWithMSAL(audienceUri);
            if (result == null)
            {
                Console.WriteLine("Canceling attempt to call func app.\n");
                return null;
            }

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

            // Create the multipart form data content
            var content = new MultipartFormDataContent();

            // In-memory data
            byte[] inMemoryData = System.Text.Encoding.UTF8.GetBytes("This is the in-memory data content.");
            var fileContent = new ByteArrayContent(inMemoryData)
            {
                Headers = { ContentType = new MediaTypeHeaderValue("application/octet-stream") }
            };
            content.Add(fileContent, "file", "inMemoryData.txt"); // Replace "file" with the name expected by the API

            // Send the POST request
            var response = await httpClient.PostAsync(funcAppUrl, content);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                Console.WriteLine($"Failed to call func app.\nError:  {response.ReasonPhrase}\n");
                return null;
            }
        }

        private static async Task<AuthenticationResult> GetAccessTokenWithMSAL(string resourceId)
        {
            var cert = GetCertificateFromLocalStore(certName);
            if (cert == null)
            {
                Console.WriteLine($"Cannot find active certificate '{certName}' in the local store. Please check configuration");
                return null;
            }

            var app = ConfidentialClientApplicationBuilder.Create(clientId)
                .WithAuthority(new Uri(authority))
                .WithCertificate(cert)
                .Build();

            string[] scopes = new string[] { $"{resourceId}/.default" };

            var result = await app.AcquireTokenForClient(scopes).ExecuteAsync();
            Console.WriteLine($"Aquired token: \n{result.AccessToken}");
            return result;
        }

        private static X509Certificate2 GetCertificateFromLocalStore(string certName)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var certCollection = store.Certificates.Find(X509FindType.FindBySubjectName, certName, false);
                if (certCollection.Count > 0)
                {
                    return certCollection[0];
                }
                else
                {
                    Console.WriteLine($"Cannot find certificate '{certName}' in the local store.");
                    return null;
                }
            }
        }
    }
}
