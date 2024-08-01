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
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string keyVaultUri = ConfigurationManager.AppSettings["ida:KeyVaultUri"];
        private static string certName = ConfigurationManager.AppSettings["ida:CertName"];

        static string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        private static HttpClient httpClient = new HttpClient();

        private static string audienceUri = ConfigurationManager.AppSettings["ida:AudienceUri"];

        private static string funcAppUrl = ConfigurationManager.AppSettings["ida:FunctionUrl"];

        static void Main(string[] args)
        {
            try
            {
                var result = CallAPI().Result;
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
            AuthenticationResult result = await GetAccessTokenWithMSAL(audienceUri);
            if (result == null)
            {
                Console.WriteLine("Canceling attempt to call func app.\n");
                return null;
            }
            else
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

                // Create the multipart form data content
                var content = new MultipartFormDataContent();

                // In-memory data
                byte[] inMemoryData = System.Text.Encoding.UTF8.GetBytes("This is the in-memory data content.");
                var fileContent = new ByteArrayContent(inMemoryData);
                fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                content.Add(fileContent, "file", "inMemoryData.txt"); // Replace "file" with the name expected by the API

                // Send the POST request
                HttpResponseMessage response = await httpClient.PostAsync(funcAppUrl, content);
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
        }

        private static async Task<AuthenticationResult> GetAccessTokenWithMSAL(string resourceId)
        {
            var cert = GetCertificateFromLocalStore(certName);
            if (cert == null)
            {
                Console.WriteLine($"Cannot find active certificate '{certName}' in Azure Key Vault. Please check configuration");
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
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindBySubjectName, certName, false);
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
