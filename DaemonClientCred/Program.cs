using Microsoft.Identity.Client;
using System;
using System.Configuration;
using System.Globalization;
using System.IO;
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
        private static readonly string storeLocationConfig = ConfigurationManager.AppSettings["ida:StoreLocation"];
        private static readonly string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly string audienceUri = ConfigurationManager.AppSettings["ida:AudienceUri"];
        private static readonly string funcAppUrl = ConfigurationManager.AppSettings["ida:FunctionUrl"];

        static async Task Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine($"Enter command (h = {nameof(GetHistoryData)}, s = {nameof(GetSecurityHistory)}, ho = {nameof(Hello)}, x = {nameof(GetComplexData)}, q = quit):");
                var command = Console.ReadLine();

                if (command.Equals("q", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                try
                {
                    string result;
                    switch (command)
                    {
                        case "s":
                            result = await GetSecurityHistory();
                            break;
                        case "h":
                            result = await GetHistoryData();
                            break;
                        case "ho":
                            result = await Hello();
                            break;
                        case "x":
                            result = await GetComplexData();
                            break;
                        default:
                            result = "Invalid command";
                            break;
                    }

                    Console.WriteLine($"Here is the result: {result}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }
        }

        static async Task<string> GetSecurityHistory()
        {
            string xmlContent = await GetFile();
            return await CallAPI(nameof(GetSecurityHistory), xmlContent);
        }

        static async Task<string> GetHistoryData()
        {
            string xmlContent = await GetFile();
            return await CallAPI(nameof(GetHistoryData), xmlContent);
        }

        private static async Task<string> GetFile()
        {
            string xmlFilePath = "test.xml";
            return await ReadXmlFileAsync(xmlFilePath);
        }

        static async Task<string> Hello()
        {
            return await CallAPI(nameof(Hello), null);
        }

        static async Task<string> GetComplexData()
        {
            return await CallAPI(nameof(GetComplexData), null);
        }

        static async Task<string> CallAPI(string endpoint, string xmlContent)
        {
            var result = await GetAccessTokenWithMSAL(audienceUri);
            if (result == null)
            {
                Console.WriteLine("Canceling attempt to call func app.\n");
                return null;
            }

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

            HttpContent content;
            if (xmlContent != null)
            {
                content = new StringContent(xmlContent);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/xml");
            }
            else
            {
                // In-memory data for the "hello" and "complexData" endpoints
                byte[] inMemoryData = System.Text.Encoding.UTF8.GetBytes("test.xml");
                var fileContent = new ByteArrayContent(inMemoryData)
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("application/octet-stream") }
                };
                content = new MultipartFormDataContent
                {
                    { fileContent, "file", "test.xml" } // Replace "file" with the name expected by the API
                };
            }

            var targetfunc = $"{funcAppUrl}api/v1/{endpoint}";
            Console.WriteLine($"Calling {targetfunc}");

            // Send the POST request
            var response = await httpClient.PostAsync(targetfunc, content);
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

        private static async Task<string> ReadXmlFileAsync(string filePath)
        {
            using (StreamReader reader = new StreamReader(filePath))
            {
                return await reader.ReadToEndAsync();
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
            var storeLocation = storeLocationConfig.Equals("LocalMachine", StringComparison.OrdinalIgnoreCase)
                ? StoreLocation.LocalMachine
                : StoreLocation.CurrentUser;

            using (var store = new X509Store(StoreName.My, storeLocation))
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
