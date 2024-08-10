using Microsoft.Identity.Client;
using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace DaemonClientCred
{
    class Program
    {
        private const string inputFile = "test.xml";
        private static IConfiguration configuration;
        private static readonly HttpClient httpClient = new HttpClient();
        private static string aadInstance;
        private static string tenant;
        private static string clientId;
        private static string certName;
        private static string storeLocationConfig;
        private static string authority;
        private static string audienceUri;
        private static string funcAppUrl;

        static async Task Main()
        {
            // Set up configuration sources
            var environment = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "Production";

            configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{environment}.json", optional: true, reloadOnChange: true)
                .Build();

            // Initialize configuration values
            InitializeConfigurationValues();

            await ProcessCommands();
        }

        private static void InitializeConfigurationValues()
        {
            aadInstance = configuration["AzureAd:AADInstance"];
            tenant = configuration["AzureAd:Tenant"];
            clientId = configuration["AzureAd:ClientId"];
            authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
            audienceUri = configuration["AzureAd:AudienceUri"];
            funcAppUrl = configuration["AzureAd:FunctionUrl"];

            certName = configuration["CertName"];
            storeLocationConfig = configuration["StoreLocation"];
        }

        private static async Task ProcessCommands()
        {
            while (true)
            {
                Console.Write($"{Environment.NewLine}Enter command (h = ");
                WriteColored(nameof(GetHistoryData), ConsoleColor.Green);

                Console.Write(", s = ");
                WriteColored(nameof(GetSecurityHistory), ConsoleColor.Green);

                Console.Write(", x = ");
                WriteColored(nameof(GetComplexData), ConsoleColor.Green);

                Console.Write(", ho = ");
                WriteColored(nameof(Hello), ConsoleColor.Green);

                Console.WriteLine(", q = quit) and hit enter:");

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

                    WriteColored($"{Environment.NewLine}Here is the result: ", ConsoleColor.Yellow);
                    Console.WriteLine(result);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }
        }
        
        static async Task<string> GetSecurityHistory()
        {
            return await CallAPI(nameof(GetSecurityHistory), await ReadXmlFileAsync(inputFile));
        }

        static async Task<string> GetHistoryData()
        {
            return await CallAPI(nameof(GetHistoryData), await ReadXmlFileAsync(inputFile));
        }

        static async Task<string> Hello()
        {
            return await CallAPI(nameof(Hello), null);
        }

        static async Task<string> GetComplexData()
        {
            return await CallAPI(nameof(GetComplexData), await ReadXmlFileAsync(inputFile));
        }

        static async Task<string> CallAPI(string endpoint, string xmlContent)
        {
            var result = await GetAccessTokenWithMSAL(audienceUri);
            if (result == null)
            {
                Console.WriteLine($"Canceling attempt to call func app.{Environment.NewLine}");
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
                byte[] inMemoryData = System.Text.Encoding.UTF8.GetBytes(inputFile);
                var fileContent = new ByteArrayContent(inMemoryData)
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("application/octet-stream") }
                };
                content = new MultipartFormDataContent { { fileContent, "file", inputFile } };
            }

            var targetfunc = string.Concat(funcAppUrl, "api/v1/", endpoint);
            Console.WriteLine($"{Environment.NewLine}Calling: {targetfunc}");

            // Send the POST request
            var response = await httpClient.PostAsync(targetfunc, content);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                Console.WriteLine($"Failed to call func app.{Environment.NewLine}Error:  {response.ReasonPhrase}\n");
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
            Console.WriteLine($"{Environment.NewLine}Aquired token: {Environment.NewLine}{result.AccessToken}");
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

        private static void WriteColored(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }
    }
}
