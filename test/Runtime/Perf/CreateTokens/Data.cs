//-------------------------------------------------------------------------------------------------
// <copyright file="Data.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Claims;

namespace RuntimeTests
{
    public static class Data
    {
        public static string Audience { get => "http://Audience"; }

        public static string AuthenticationType { get => "LocalUser"; }

        public static IDictionary<string, object> ClaimsDictionary
        {
            get => new Dictionary<string, object>
            {
                { ClaimTypes.Country, "USA" },
                { ClaimTypes.NameIdentifier, "Bob" },
                { ClaimTypes.Email, "Bob@contoso.com" },
                { ClaimTypes.GivenName, "Bob" },
                { ClaimTypes.HomePhone, "555.1212" },
                { ClaimTypes.Role, "Developer" },
                { ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA" },
                { ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien" }
            };
        }

        public static List<Claim> Claims
        {
            get => new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, Issuer, OriginalIssuer),
            };
        }

        public static string Issuer { get => "http://issuer.com"; }

        public static string OriginalIssuer { get => "http://originalIssuer.com"; }

        public static ClaimsIdentity Subject { get => new ClaimsIdentity(Claims, AuthenticationType); }
    }
}
