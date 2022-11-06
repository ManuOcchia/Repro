




using FastEndpoints;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Repro;
using System.Security.Cryptography;
using System.Text;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddFastEndpoints();

builder.Services.AddAuthentication(o =>
{
    o.DefaultChallengeScheme = Settings.SCHEME;
    o.DefaultAuthenticateScheme = Settings.SCHEME;
})
      .AddJwtBearer(Settings.SCHEME, o =>
      {
          o.Events = new JwtBearerEvents();

          o.Events.OnMessageReceived = context =>
          {
              context.Request.Cookies.TryGetValue(Settings.COOKIE_NAME, out var jwtFromCookie);
              context.Token = jwtFromCookie;
              return Task.CompletedTask;
          };

          o.Events.OnChallenge = context =>
             throw new UnauthorizedAccessException();


          o.TokenValidationParameters = new()
          {
              ValidateIssuer = true,
              ValidateLifetime = true,
              ValidateAudience = true,
              ClockSkew = TimeSpan.Zero,
              RequireExpirationTime = false,
              ValidateIssuerSigningKey = true,
              LifetimeValidator = (DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters) => expires is not null ? expires > DateTime.UtcNow : false,
              ValidIssuer = Settings.ISSUER,
              ValidAudience = Settings.AUDIENCE,
              IssuerSigningKey = new SymmetricSecurityKey(new HMACSHA512(Encoding.UTF8.GetBytes(Settings.JWT_KEY)).Key)
          };
      });

builder.Services.AddAuthorization(opt =>
       opt.AddPolicy(
           Settings.POLICY,
           policy =>
           {
               policy.AuthenticationSchemes.Add(Settings.SCHEME);
               policy.RequireAuthenticatedUser();
           })
   );

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseAuthentication();
app.UseAuthorization();
app.UseFastEndpoints();

app.Run();
