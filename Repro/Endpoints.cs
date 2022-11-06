using FastEndpoints;
using FastEndpoints.Security;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Repro;


[HttpPost(URL), AllowAnonymous]
public class UserLoginEndpoint : Endpoint<EmptyRequest, string>
{
    public const string URL = "login";

    public override async Task HandleAsync(EmptyRequest req, CancellationToken ct)
    {
        var claims = new List<Claim> {
            new Claim("username", "testEmail@email.com"),
            new Claim(type: ClaimTypes.NameIdentifier, "myTestId"),
        };

        var token = JWTBearer.CreateToken(
          expireAt: DateTime.UtcNow.AddMinutes(60.0),
          signingKey: Settings.JWT_KEY,
          claims: claims,
          issuer: Settings.ISSUER,
          audience: Settings.AUDIENCE,
          roles: new List<string>() { }.AsEnumerable()
        );

        await SendAsync(token, cancellation: ct);
    }
}


[HttpGet(URL), Authorize(Policy = Settings.POLICY)]
public class TestAuthenticationEndpoint : EndpointWithoutRequest
{
    public const string URL = "test";
    public override async Task HandleAsync(CancellationToken ct)
    {
        await SendOkAsync();
    }
}
