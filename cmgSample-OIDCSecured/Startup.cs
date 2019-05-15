using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
// added this import to support OIDC support
using Microsoft.AspNetCore.Authentication.JwtBearer;
using cmgSample_OIDCSecured.Security;
using Microsoft.IdentityModel.Logging;

namespace cmgSample_OIDCSecured
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // Replace your ConfigureServices method with the following:
        public void ConfigureServices(IServiceCollection services)
        {
            // Add service and create Policy with options
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader());
            });
            // Change compatibility mode to 2_2
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
            // This is the .Net core JWT Authentication Service
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
           .AddJwtBearer(options =>
           {
               //This OIDC Discovery URL should be pulled from the environment parameters.
               //Each consuming app should get their own client_id and subscribe to the OIDC Discovery API in the approriate catalog. 
               options.MetadataAddress = Configuration["OIDCDiscoveryURL"];

               // Hook into the custom JWT event handler class which performs custom claims mapping and error handling.
               options.Events = JwtEventHandler.CreateJwtEvents();
               options.Audience = "Company:JWT";               
           }

           );

            //this is an example of how to connect an Authorization policy. 
            //"SiteAdmin" policy which requires a specific claim value to map true for authorization to pass.
            //RoleGroup can be pulled from the environment configuration.
            services.AddAuthorization(options =>
            {
                options.AddPolicy("IsInRoleForLookUpsPolicy", policy =>
                                policy.RequireRole(Configuration["LookUpRoleGroup"]) );
            });

            // This property can be used to troubleshoot JWT validation errors. It adds more details for validation errors.
            //It can be commented out for production deploy.
            //It also requires Microsoft.IdentityModel.Logging;

            IdentityModelEventSource.ShowPII = true;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            // This line below is required to wire up JWT authentication.
            app.UseAuthentication();
            app.UseCors("CorsPolicy");

            app.UseMvc();
        }

        
    }
}
