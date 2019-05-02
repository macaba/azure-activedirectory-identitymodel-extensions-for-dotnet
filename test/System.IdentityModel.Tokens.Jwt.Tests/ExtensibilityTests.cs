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

using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    /// <summary>
    /// TokenValidation extensibility scenarios
    /// </summary>
    public class ExtensibilityTests
    {
        [Theory, MemberData(nameof(ValidateVirtualCallGraphTheoryData))]
        public void ValidateVirtualCallGraph(ValidateTokenVirtualTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateVirtualCallGraph", theoryData);

            try
            {
                theoryData.TokenHandler.ValidateToken(theoryData.Token, theoryData.TokenValidationParameters, out SecurityToken validatedToken);

                if (!theoryData.TokenHandler.CreateClaimsIdentityCalled)
                    context.AddDiff("!handler.CreateClaimsIdentityCalled");

                if (!theoryData.TokenHandler.ReadTokenCalled)
                    context.AddDiff("!handler.ReadTokenCalled");

                if (!theoryData.TokenHandler.ResolveIssuerSigningKeyCalled)
                    context.AddDiff("!handler.ResolveIssuerSigningKeyCalled");

                if (!theoryData.TokenHandler.ResolveTokenDecryptionKeyCalled)
                    context.AddDiff("!handler.ResolveTokenDecryptionKeyCalled");

                if (!theoryData.TokenHandler.ValidateAudienceCalled)
                    context.AddDiff("!handler.ValidateAudienceCalled");

                if (!theoryData.TokenHandler.ValidateIssuerCalled)
                    context.AddDiff("!handler.ValidateIssuerCalled");

                if (!theoryData.TokenHandler.ValidateIssuerSigningKeyCalled)
                    context.AddDiff("!handler.ValidateIssuerSigningKeyCalled");

                if (!theoryData.TokenHandler.ValidateLifetimeCalled)
                    context.AddDiff("!handler.ValidateLifetimeCalled");

                if (!theoryData.TokenHandler.ValidateSignatureCalled)
                    context.AddDiff("!handler.ValidateSignatureCalled");

                if (!theoryData.TokenHandler.ValidateTokenCalled)
                    context.AddDiff("!handler.ValidateTokenCalled");

                if (!theoryData.TokenHandler.ValidateTokenReplayCalled)
                    context.AddDiff("!handler.ValidateTokenCalled");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenVirtualTheoryData> ValidateVirtualCallGraphTheoryData
        {
            get
            {
                var tokenHandler = new JsonWebTokenHandler();
                return new TheoryData<ValidateTokenVirtualTheoryData>
                {
                    new ValidateTokenVirtualTheoryData
                    {
                        Token = tokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials, KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512),
                        TokenHandler = new DerivedJwtSecurityTokenHandler(),
                        TokenValidationParameters =  new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    }
                };
            }
        }


        public class ValidateTokenVirtualTheoryData : TheoryDataBase
        {
            public string Token { get; set; }

            public IDerivedSecurityTokenHandler TokenHandler { get; set; }

            public TokenValidationParameters TokenValidationParameters{ get; set; }
        }
    }

    #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
}
