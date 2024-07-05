using System.Net.Http.Headers;

namespace DPoPFlowDebugger;

/// <summary>
/// This handler assumes the caller will build their request as usual - including the token in the Authorization header
/// </summary>
/// <param name="keyPair"></param>
[Obsolete("Reorg, WIP", true)]
public class DPoPProofedHttpHandler(DPoPClient client) : DelegatingHandler
{
    private readonly DPoPClient _client = client;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Headers.Contains("DPoP"))
        {
            request.Headers.Remove("DPoP");
        }

        switch (request.Headers.Authorization?.Scheme)
        {
            // if the scheme is Bearer, we need to replace it with DPoP
            // this would likely make sense as an option (E.g., Force DPoP, Use DPoP if available, etc.)
            // would be helpful for migrating code bases
            case "Bearer":
                request.Headers.Remove("Authorization");
                request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", request.Headers.Authorization.Parameter);
                break;
            case "DPoP":
                // if we already have a DPoP authorization scheme, all we need to do is tack on the DPoP proof header
                break;
            default:
                // if the scheme isn't Bearer or DPoP, we aren't involved so time to go
                return await base.SendAsync(request, cancellationToken);
        }

        var proof = _client.BuildDPoPProof(request.RequestUri?.ToString(), request.Method.Method, true);

        // note the scheme here is DPoP
        request.Headers.Add("DPoP", proof);
        return await base.SendAsync(request, cancellationToken);
    }
}
