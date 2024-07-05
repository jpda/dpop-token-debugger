
using Microsoft.Extensions.Logging;

namespace DPoPFlowDebugger;

internal class Program
{
    private static readonly HttpClient _httpClient = new();
    // token endpoint for your AS
    private const string TOKEN_ENDPOINT = "https://t1.local.devenv.lol/connect/token";
    // the protected API to call
    private const string API_ENDPOINT = "https://t1.local.devenv.lol/api/v0.1/identity";
    // the scope for that API
    private const string API_SCOPE = "some-scope";
    private const string CLIENT_ID = "tokendebugger";
    private const string CLIENT_SECRET = "some-secret";
    private const string CLIENT_REDIRECT_URI = "https://oauth.studio/code";

    private static readonly ILoggerFactory _loggerFactory = LoggerFactory.Create(static builder => builder.AddConsole());

    private static async Task Main(string[] args)
    {
        // create a set of keys to use for this set of requests.
        // the key will be needed to make any requests using the AT, or to refresh the AT
        var client = new DPoPClient(
            new Uri(TOKEN_ENDPOINT),
            new ClientApplication(CLIENT_ID, CLIENT_SECRET, CLIENT_REDIRECT_URI),
            _httpClient,
            _loggerFactory.CreateLogger<DPoPClient>()
        );

        var response = await client.Get(API_ENDPOINT);
        var content = await response.Content.ReadAsStringAsync();
        if (response.IsSuccessStatusCode)
        {
            Console.WriteLine(content);
        }
        else
        {
            Console.WriteLine($"Failed: {response.StatusCode}, {content}");
        }
    }
}