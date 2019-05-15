using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;

// Added these imports
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Diagnostics;
using System.Security.Claims;


namespace cmgSample_OIDCSecured.Security
{
    /// <summary>
    /// A JWT validation event handler.
    /// </summary>
    public static class JwtEventHandler
    {
        /// <summary>
        /// Creates one or more JWT event handlers.
        /// </summary>
        /// <returns>
        /// A JwtBearerEvents object instance.
        /// </returns>
        public static JwtBearerEvents CreateJwtEvents()
        {
            var events = new JwtBearerEvents
            {
                // This event happens when the JWT token is present, but is not valid
                OnAuthenticationFailed = context =>
                {
                    Debug.WriteLine("OnAuthenticationFailed: " + context.Exception.Message);

                    return Task.FromResult(0);
                },
                // This event happens when the JWT token is valid.
                // the logic inspects the JWT token for claims, and converts them
                // to standard Microsoft claims so the built-in .NET functionality can be used
                // e.g. [Authorize(Roles = "Everyone")] decoration
                OnTokenValidated = context =>
                {
                    Debug.WriteLine("OnTokenValidated: " + context.SecurityToken);
                    // re-adding as claims which .net core understands for some standard role-based authorization
                    var claims = new List<Claim>();

                    // evaluate the "username" claim in the token, and convert to a Microsoft Role claim with a value of "Everyone"
                    //populating custom claim - can be used to embed custom security info
                    int claimUserIDVal = context.Principal.Claims.Where(c => c.Type == "username" && c.Value.Length > 0).Count();

                    if (claimUserIDVal > 0)
                    {
                        claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Everyone"));
                    }

                    // iterate through the "MemberOf" claim in the token, and convert to .NET claims (one claim for each role group)
                    // Example value: "memberof": "CN=R-App-CSM-AASSecondLevelSupport:CN=R-SERVICEGATEWAY-MyInvestmentView-NonProd:CN=R-SERVICEGATEWAY-MyInvestmentView-P:CN=R-App-Pkg-Microsoft_VisualStudio_2017:CN=R-App-Pkg-AltovaXMLSpy2018"
                    int claimMemberOfVal = context.Principal.Claims.Where(c => c.Type == "memberof" && c.Value.Length > 0).Count();
                    if (claimMemberOfVal > 0)
                    {
                        string[] membersofList = context.Principal.Claims.Where(c => c.Type == "memberof").FirstOrDefault().Value.ToString().Split(":");
                        foreach (string strmemberof in membersofList)
                        {
                            claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", strmemberof.Split(",")[0].Replace("CN=", "")));
                        }
                    }

                    if (claims.Count > 0)
                    {
                        // claims were found in the token and converted to Microsoft claims,
                        // so add them to the context Principal
                        var appIdentity = new ClaimsIdentity(claims);
                        context.Principal.AddIdentity(appIdentity);
                    }

                    return Task.FromResult(0);
                }
            };

            return events;
        }
    }
}
