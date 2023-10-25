using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Restaurant.Identity.Application.Services;
using Restaurant.Identity.Infrastructure.Config;
using Restaurant.Identity.Infrastructure.EF;
using Restaurant.Identity.Infrastructure.PersistenceModel;
using Restaurant.Identity.Infrastructure.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Restaurant.Identity.Infrastructure
{
    public static class Extensions
    {

        private static void AddSecurity(IServiceCollection services, IConfiguration configuration)
        {

            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.Password.RequiredLength = 8;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                options.Lockout.MaxFailedAccessAttempts = 5;
            }).AddEntityFrameworkStores<SecurityDbContext>()
            .AddDefaultTokenProviders();

            services.AddScoped<SecurityInitializer>();

            services.AddAuthorization(config =>
            {
                var defaultAuthBuilder = new AuthorizationPolicyBuilder();
                var defaultAuthPolicy = defaultAuthBuilder
                    .RequireAuthenticatedUser()
                    .Build();

                config.DefaultPolicy = defaultAuthPolicy;

                foreach (var mnemonic in ApplicationPermission.GetAllPermissions().Select(x => x.Mnemonic))
                {
                    config.AddPolicy(mnemonic,
                        policy => policy.RequireClaim("Permission", new string[] { mnemonic }));
                }
            });

            JwtOptions jwtoptions = configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer("Bearer", jwtOptions =>
            {
                var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtoptions.SecretKey));
                jwtOptions.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateIssuer = jwtoptions.ValidateIssuer,
                    ValidateAudience = jwtoptions.ValidateAudience,
                    ValidIssuer = jwtoptions.ValidIssuer,
                    ValidAudience = jwtoptions.ValidAudience
                };
            });
            services.AddSingleton(jwtoptions);

            
            services.AddScoped<ISecurityService, SecurityService>();

        }

        private static void AddDatabase(IServiceCollection services, IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("DbConnectionString");

            services.AddDbContext<SecurityDbContext>(ctx =>
                ctx.UseSqlServer(connectionString));
                        
        }

        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {

            AddDatabase(services, configuration);
            AddSecurity(services, configuration);

            return services;
        }
    }
}
