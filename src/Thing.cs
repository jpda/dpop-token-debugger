using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace DPoPFlowDebugger;

public class DPoPKeyPair
{
    public DPoPKeyPair()
    {
        Key = CreateRsaSecurityKey();
        SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.RsaSha256);
        GenerateJwkHeader();
    }

    // jpd: yanked from the MSAL tests 
    private RsaSecurityKey CreateRsaSecurityKey()
    {
        RSA rsa = new RSACryptoServiceProvider(2048);

        // the reason for creating the RsaSecurityKey from RSAParameters is so that a SignatureProvider created with this key
        // will own the RSA object and dispose it. If we pass a RSA object, the SignatureProvider does not own the object, the RSA object will not be disposed.
        RSAParameters rsaParameters = rsa.ExportParameters(true);
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = CreateRsaKeyId(rsaParameters) };
        rsa.Dispose();
        return rsaSecurityKey;
    }

    private static string CreateRsaKeyId(RSAParameters rsaParameters)
    {
        byte[] kidBytes = new byte[rsaParameters.Exponent.Length + rsaParameters.Modulus.Length];
        Array.Copy(rsaParameters.Exponent, 0, kidBytes, 0, rsaParameters.Exponent.Length);
        Array.Copy(rsaParameters.Modulus, 0, kidBytes, rsaParameters.Exponent.Length, rsaParameters.Modulus.Length);
        return Base64UrlEncoder.Encode(SHA256.HashData(kidBytes));
    }

    public RsaSecurityKey Key { get; }
    public SigningCredentials SigningCredentials { get; }

    public object GenerateJwkHeader()
    {
        return new
        {
            kty = JsonWebAlgorithmsKeyTypes.RSA,
            alg = SecurityAlgorithms.RsaSha256,
            use = JsonWebKeyUseNames.Sig,
            e = Base64UrlEncoder.Encode(Key.Parameters.Exponent),
            n = Base64UrlEncoder.Encode(Key.Parameters.Modulus),
        };
    }
}

internal record TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = null!;

    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = null!;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; } = 0;

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = null!;
}

public record ClientApplication(string ClientId, string ClientSecret, string RedirectUri);

public class DPoPClient(Uri tokenEndpoint, ClientApplication clientApp, HttpClient httpClient, ILogger<DPoPClient> logger)
{
    private readonly HttpClient _httpClient = httpClient;
    private readonly string _clientId = clientApp.ClientId;
    private readonly string? _clientSecret = clientApp.ClientSecret;
    private readonly string _clientRedirectUri = clientApp.RedirectUri;
    private readonly DPoPKeyPair _key = new();
    private readonly Uri _tokenEndpoint = tokenEndpoint;
    private readonly ILogger<DPoPClient> _logger = logger;

    private TokenResponse? _token = null;

    /// <summary>
    /// Builds a DPoP proof for a given URL and HTTP method, used on every request using a bound access token
    /// </summary>
    /// <param name="url"></param>
    /// <param name="httpMethod"></param>
    /// <param name="includeAtHash"></param>
    /// <returns></returns>
    internal string BuildDPoPProof(string url, string httpMethod, bool includeAtHash = false)
    {
        using var _ = _logger.BeginScope("Building DPoP proof for {url}", url);
        _logger.LogInformation("Building DPoP proof for {url}", url);
        var header = new JwtHeader(
            signingCredentials: _key.SigningCredentials,
            outboundAlgorithmMap: new Dictionary<string, string> { { SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha256 } },
            tokenType: "dpop+jwt") {
            { "jwk", JsonSerializer.SerializeToElement(_key.GenerateJwkHeader()) }
        };

        var payload = new JwtPayload
        {
            { "htu", url },
            { "htm", httpMethod },
            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
            { "jti", Guid.NewGuid().ToString() }
        };

        if (includeAtHash)
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(_token!.AccessToken));
            var ath = Base64UrlEncoder.Encode(hash);

            payload.Add("ath", ath);
        }

        var jwt = new JwtSecurityToken(header, payload)
        {
            SigningKey = _key.Key
        };

        var handler = new JwtSecurityTokenHandler();
        var jwtString = handler.WriteToken(jwt);
        _logger.LogInformation("DPoP proof: {jwt}", jwtString);
        return jwtString;
    }

    private async Task<TokenResponse> RequestToken(Dictionary<string, string> form)
    {
        if (_token is not null)
        {
            return _token;
        }

        _httpClient.DefaultRequestHeaders.Clear();
        var dpopProof = BuildDPoPProof(_tokenEndpoint.ToString(), HttpMethod.Post.Method, false);
        _httpClient.DefaultRequestHeaders.Add("DPoP", dpopProof);
        var response = await _httpClient.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(form));
        var content = await response.Content.ReadAsStringAsync();
        _token = JsonSerializer.Deserialize<TokenResponse>(content) ?? throw new Exception("Failed to get token");
        _httpClient.DefaultRequestHeaders.Clear();
        return _token;
    }

    /// <summary>
    /// Use this when redeeming the client's credentials for an access token.
    /// Client creds aren't the primary case for DPoP, but it's a good way to see what's going on
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    private async Task<TokenResponse> RequestTokenForClient(params string[] scopes)
    {
        return await RequestToken(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = string.Join(' ', scopes),
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret!
        });
    }

    /// <summary>
    /// Use this when redeeming the user's authorization code for an access token
    /// </summary>
    /// <param name="code"></param>
    /// <param name="codeVerifier"></param>
    /// <param name="scopes"></param>
    /// <returns></returns>
    private async Task<TokenResponse> RequestTokenForUser(string code, string codeVerifier, params string[] scopes)
    {
        return await RequestToken(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = _clientRedirectUri,
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret!,
            ["scope"] = string.Join(' ', scopes),
            ["code_verifier"] = codeVerifier
        });
    }

    public async Task<HttpResponseMessage> Get(string url)
    {
        // first we need to get a DPoP-bound AT
        var token = await RequestTokenForClient();

        // wipe out our headers
        _httpClient.DefaultRequestHeaders.Clear();

        // add the AT to the headers but with the DPoP scheme
        // e.g., Authorization: DPoP <AT>
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("DPoP", token.AccessToken);

        // now build a proof for this request URI/method - essentially a signed JWT that includes the method + URL
        // and is signed with the same JWK we used in the original AT request
        // because it is using the AT, we include the AT hash in the proof
        var proof = BuildDPoPProof(url, HttpMethod.Get.Method, true);

        // add that to the DPoP _header_
        // surely the DPoP header and the DPoP scheme will *never* get confused 🫠
        _httpClient.DefaultRequestHeaders.Add("DPoP", proof);

        // fire when ready
        return await _httpClient.GetAsync(url);
    }
}