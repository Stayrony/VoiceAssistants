using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Common.Options;
using Common.Providers;
using Common.Providers.Contract;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace VoiceAssistants.Authorization
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //options
            services.AddOptions();
            services.AddDataProtection();
            services.Configure<JwtTokenOptions>(Configuration.GetSection("JwtToken"));

            services.AddTransient<ITokenProvider, TokenProvider>();

            ServiceProvider serviceProvider = services.BuildServiceProvider();
            ITokenProvider tokenProvider = serviceProvider.GetRequiredService<ITokenProvider>();

            services.AddAuthentication(authOpts =>
            {
                authOpts.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                authOpts.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                authOpts.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(bearerOpts =>
            {
                //ADDRESS OF IDENTITY SRV
                bearerOpts.Authority = tokenProvider.TokenInfo.Authority;
                bearerOpts.Audience = tokenProvider.TokenInfo.Issuer;
                bearerOpts.IncludeErrorDetails = true;

                bearerOpts.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = tokenProvider.TokenInfo.ValidateIssuer,
                    ValidateLifetime = tokenProvider.TokenInfo.ValidateLifetime,
                    ValidateIssuerSigningKey = tokenProvider.TokenInfo.ValidateIssuerSigningKey,
                    ValidateAudience = tokenProvider.TokenInfo.ValidateAudience,
                    //ClockSkew = tokenProvider.TokenInfo.ClockSkew,

                    ValidIssuer = tokenProvider.TokenInfo.Issuer,
                    ValidAudience = tokenProvider.TokenInfo.Audience,
                    IssuerSigningKey =
                        new SymmetricSecurityKey(Encoding.ASCII.GetBytes(tokenProvider.TokenInfo.IssuerSecurityKey))
                };

                bearerOpts.RequireHttpsMetadata = false;
                bearerOpts.Events = new JwtBearerEvents()
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.NoResult();

                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "text/plain";

                        return context.Response.WriteAsync(context.Exception.ToString());
                    }
                };
            }).AddCookie("dummy");

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseMvc();
        }
    }
}
