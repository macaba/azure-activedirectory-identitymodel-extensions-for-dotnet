//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public interface IDerivedSecurityTokenHandler  : ISecurityTokenValidator
    {

        bool CreateActorValueCalled { get; set; }

        bool CreateClaimsIdentityCalled { get; set; }

        bool ReadTokenCalled { get; set; }

        bool ResolveIssuerSigningKeyCalled { get; set; }

        bool ResolveTokenDecryptionKeyCalled { get; set; }

        bool ValidateAudienceCalled { get; set; }

        bool ValidateIssuerCalled { get; set; }

        bool ValidateLifetimeCalled { get; set; }

        bool ValidateIssuerSigningKeyCalled { get; set; }

        bool ValidateSignatureCalled { get; set; }

        bool ValidateTokenCalled { get; set; }

        bool ValidateTokenReplayCalled { get; set; }
    }

    /// <summary>
    /// Ensures that all protected types use same token.
    /// </summary>
    public class DerivedJwtSecurityTokenHandler : JwtSecurityTokenHandler, IDerivedSecurityTokenHandler
    {
        public DerivedJwtSecurityTokenHandler()
        {
        }

        public bool CreateActorValueCalled { get; set; } = false;

        public bool CreateClaimsIdentityCalled { get; set; } = false;

        public bool ReadTokenCalled { get; set; } = false;

        public bool ResolveIssuerSigningKeyCalled { get; set; } = false;

        public bool ResolveTokenDecryptionKeyCalled { get; set; } = false;

        public bool ValidateAudienceCalled { get; set; } = false;

        public bool ValidateIssuerCalled { get; set; } = false;

        public bool ValidateIssuerSigningKeyCalled { get; set; } = false;

        public bool ValidateLifetimeCalled { get; set; } = false;

        public bool ValidateSignatureCalled { get; set; } = false;

        public bool ValidateTokenCalled { get; set; } = false;

        public bool ValidateTokenReplayCalled { get; set; } = false;

        public JwtSecurityToken Jwt { get; set; }

        public override SecurityToken ReadToken(string token)
        {
            ReadTokenCalled = true;
            return base.ReadToken(token);
        }

        protected override string CreateActorValue(ClaimsIdentity actor)
        {
            CreateActorValueCalled = true;
            return base.CreateActorValue(actor);
        }

        protected override ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwtToken, string issuer, TokenValidationParameters validationParameters)
        {
            CreateClaimsIdentityCalled = true;
            return base.CreateClaimsIdentity(jwtToken, issuer, validationParameters);
        }

        protected override SecurityKey ResolveIssuerSigningKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
        {
            ResolveIssuerSigningKeyCalled = true;
            return base.ResolveIssuerSigningKey(token, jwtToken, validationParameters);
        }

        protected override SecurityKey ResolveTokenDecryptionKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
        {
            ResolveTokenDecryptionKeyCalled = true;
            return base.ResolveTokenDecryptionKey(token, jwtToken, validationParameters);
        }

        protected override void ValidateAudience(IEnumerable<string> audiences, JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            ValidateAudienceCalled = true;
            base.ValidateAudience(audiences, jwt, validationParameters);
        }

        protected override string ValidateIssuer(string issuer, JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            ValidateIssuerCalled = true;
            return base.ValidateIssuer(issuer, jwt, validationParameters);
        }

        protected override void ValidateIssuerSecurityKey(SecurityKey securityKey, JwtSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            ValidateIssuerSigningKeyCalled = true;
            base.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        protected override void ValidateLifetime(DateTime? notBefore, DateTime? expires, JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            ValidateLifetimeCalled = true;
            base.ValidateLifetime(notBefore, expires, jwt, validationParameters);
        }

        protected override JwtSecurityToken ValidateSignature(string securityToken, TokenValidationParameters validationParameters)
        {
            ValidateSignatureCalled = true;
            return base.ValidateSignature(securityToken, validationParameters);
        }

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            ValidateTokenCalled = true;
            return base.ValidateToken(securityToken, validationParameters, out validatedToken);
        }

        protected override void ValidateTokenReplay(DateTime? expires, string securityToken, TokenValidationParameters validationParameters)
        {
            ValidateTokenReplayCalled = true;
            base.ValidateTokenReplay(expires, securityToken, validationParameters);
        }
    }

    public class PublicJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        public void DecryptTokenPublic(JwtSecurityToken token, TokenValidationParameters validationParameters)
        {
            base.DecryptToken(token, validationParameters);
        }

        public void ValidateAudiencePublic(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            base.ValidateAudience(jwt.Audiences, jwt, validationParameters);
        }

        public string ValidateIssuerPublic(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            return base.ValidateIssuer(jwt.Issuer, jwt, validationParameters);
        }

        public void ValidateLifetimePublic(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            base.ValidateLifetime(DateTime.UtcNow, DateTime.UtcNow, jwt, validationParameters);
        }

        public void ValidateSigningTokenPublic(SecurityKey securityKey, JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            base.ValidateIssuerSecurityKey(securityKey, jwt, validationParameters);
        }
    }
}
