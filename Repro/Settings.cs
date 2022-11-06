using FastEndpoints;
using FastEndpoints.Security;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Repro;


public static class Settings
{
    public const string SCHEME = "MyScheme";
    public const string COOKIE_NAME = "MyCookieName";
    public const string ISSUER = "MyIssuer";
    public const string AUDIENCE = "MyAudience";
    public const string POLICY = "MyPolicy";
    public const string JWT_KEY = "MySecretJwtTestKeyToEncrypt";
}


