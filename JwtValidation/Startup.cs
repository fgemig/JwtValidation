using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using System;
using JwtValidation.Security;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidation
{
    public class Startup
    {
        private JwtTokenOptions _options = new JwtTokenOptions();
        
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc(config =>
            {
                var policy = new AuthorizationPolicyBuilder()
                                 .RequireAuthenticatedUser()
                                 .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            });

            services.AddCors();

            services.Configure<JwtTokenOptions>(options =>
            {
                options.Issuer = _options.Issuer;
                options.Audience = _options.Audience;
                options.SigningCredentials = new SigningCredentials(_options.SigningKey, SecurityAlgorithms.HmacSha256);
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseJwtBearerAuthentication(new JwtBearerOptions()
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = _options.Issuer,

                    ValidateAudience = true,
                    ValidAudience = _options.Audience,

                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _options.SigningKey,

                    RequireExpirationTime = true,
                    ValidateLifetime = true,

                    ClockSkew = TimeSpan.Zero
                }
            });

            app.UseCors(x =>
            {
                x.AllowAnyHeader();
                x.AllowAnyMethod();
                x.AllowAnyOrigin();
            });

            app.UseMvc();
        }

    }
}
