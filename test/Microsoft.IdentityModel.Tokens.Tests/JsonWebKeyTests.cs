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

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JsonWebKeyTests
    {
        [Theory, MemberData(nameof(JsonWebKeyDataSet))]
        public void Constructors(string json, JsonWebKey compareTo, ExpectedException ee)
        {
            var context = new CompareContext();
            try
            {
                var jsonWebKey = new JsonWebKey(json);
                ee.ProcessNoException(context);
                if (compareTo != null)
                    IdentityComparer.AreEqual(jsonWebKey, compareTo, context);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<string, JsonWebKey, ExpectedException> JsonWebKeyDataSet
        {
            get
            {
                var dataset = new TheoryData<string, JsonWebKey, ExpectedException>();

                dataset.Add(null, null, ExpectedException.ArgumentNullException(substringExpected: "json"));
                dataset.Add(DataSets.JsonWebKeyFromPingString1, DataSets.JsonWebKeyFromPing1, ExpectedException.NoExceptionExpected);
                dataset.Add(DataSets.JsonWebKeyString1, DataSets.JsonWebKey1, ExpectedException.NoExceptionExpected);
                dataset.Add(DataSets.JsonWebKeyString2, DataSets.JsonWebKey2, ExpectedException.NoExceptionExpected);
                dataset.Add(DataSets.JsonWebKeyBadFormatString1, null, ExpectedException.ArgumentException(inner: typeof(JsonReaderException)));
                dataset.Add(DataSets.JsonWebKeyBadFormatString2, null, ExpectedException.ArgumentException(inner: typeof(JsonSerializationException)));
                dataset.Add(DataSets.JsonWebKeyBadX509String, DataSets.JsonWebKeyBadX509Data, ExpectedException.NoExceptionExpected);

                return dataset;
            }
        }

        [Fact]
        public void Defaults()
        {
            var context = new CompareContext();
            JsonWebKey jsonWebKey = new JsonWebKey();

            if (jsonWebKey.Alg != null)
                context.Diffs.Add("jsonWebKey.Alg != null");

            if (jsonWebKey.KeyOps.Count != 0)
                context.Diffs.Add("jsonWebKey.KeyOps.Count != 0");

            if (jsonWebKey.Kid != null)
                context.Diffs.Add("jsonWebKey.Kid != null");

            if (jsonWebKey.Kty != null)
                context.Diffs.Add("jsonWebKey.Kty != null");

            if (jsonWebKey.X5c == null)
                context.Diffs.Add("jsonWebKey.X5c == null");

            if (jsonWebKey.X5c.Count != 0)
                context.Diffs.Add("jsonWebKey.X5c.Count != 0");

            if (jsonWebKey.X5t != null)
                context.Diffs.Add("jsonWebKey.X5t != null");

            if (jsonWebKey.X5u != null)
                context.Diffs.Add("jsonWebKey.X5u != null");

            if (jsonWebKey.Use != null)
                context.Diffs.Add("jsonWebKey.Use != null");

            if (jsonWebKey.AdditionalData == null)
                context.Diffs.Add("jsonWebKey.AdditionalData == null");
            else if (jsonWebKey.AdditionalData.Count != 0)
                context.Diffs.Add("jsonWebKey.AdditionalData.Count != 0");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetSets()
        {
            JsonWebKey jsonWebKey = new JsonWebKey();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jsonWebKey, "JsonWebKey_GetSets");
            List<string> methods = new List<string> { "Alg", "Kid", "Kty", "X5t", "X5u", "Use" };
            List<string> errors = new List<string>();
            foreach (string method in methods)
            {
                TestUtilities.GetSet(jsonWebKey, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString() }, errors);
                jsonWebKey.X5c.Add(method);
            }

            CompareContext context = new CompareContext();
            if (IdentityComparer.AreEqual(jsonWebKey.X5c, methods, context))
            {
                errors.AddRange(context.Diffs);
            }

            TestUtilities.AssertFailIfErrors("JsonWebKey_GetSets", errors);
        }

        [Fact]
        public void Publics()
        {
        }

        [Theory, MemberData(nameof(IsSupportedAlgDataSet))]
        public void IsSupportedAlgorithm(JsonWebKey key, string alg, bool expectedResult)
        {
            if (key.CryptoProviderFactory.IsSupportedAlgorithm(alg, key) != expectedResult)
                Assert.True(false, string.Format("{0} failed with alg: {1}. ExpectedResult: {2}", key, alg, expectedResult));
        }

        public static TheoryData<JsonWebKey, string, bool> IsSupportedAlgDataSet
        {
            get
            {
                var dataset = new TheoryData<JsonWebKey, string, bool>();
                dataset.Add(KeyingMaterial.JsonWebKeyP256, SecurityAlgorithms.EcdsaSha256, true);
                dataset.Add(KeyingMaterial.JsonWebKeyP256, SecurityAlgorithms.RsaSha256Signature, false);
                dataset.Add(KeyingMaterial.JsonWebKeyRsa_2048, SecurityAlgorithms.RsaSha256, true);
                dataset.Add(KeyingMaterial.JsonWebKeyRsa_2048, SecurityAlgorithms.EcdsaSha256, false);
                dataset.Add(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256, true);
                dataset.Add(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.RsaSha256Signature, false);
                JsonWebKey testKey = new JsonWebKey
                {
                    Kty = JsonWebAlgorithmsKeyTypes.Octet,
                    K = KeyingMaterial.DefaultSymmetricKeyEncoded_256
                };
                testKey.CryptoProviderFactory = new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.RsaSha256Signature });
                dataset.Add(testKey, SecurityAlgorithms.RsaSha256Signature, true);
                return dataset;
            }
        }

        // Tests to make sure conditional property serialization for JsonWebKeys is working properly.
        [Fact]
        public void ConditionalPropertySerialization()
        {
            var context = new CompareContext();

            var jsonWebKeyEmptyCollections = new JsonWebKey
            {
                Alg = "SHA256",
                E = "AQAB",
                Kid = "kriMPdmBvx68skT8-mPAB3BseeA",
                Kty = "RSA",
                N = "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw==",
                X5t = "kriMPdmBvx68skT8-mPAB3BseeA",
                Use = "sig",
            };

            var jsonString1 = JsonConvert.SerializeObject(jsonWebKeyEmptyCollections);
            if (jsonString1.Contains("key_ops"))
                context.Diffs.Add("key_ops is empty and should not be present in serialized JsonWebKey");
            if (jsonString1.Contains("x5c"))
                context.Diffs.Add("x5c is empty and should not be present in serialized JsonWebKey");

            var jsonWebKeyWithCollections = new JsonWebKey();
            jsonWebKeyWithCollections.X5c.Add("MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng");
            jsonWebKeyWithCollections.KeyOps.Add("signing");
            var jsonString2 = JsonConvert.SerializeObject(jsonWebKeyWithCollections);
            if (!jsonString2.Contains("key_ops"))
                context.Diffs.Add("key_ops is non-empty and should be present in serialized JsonWebKey");
            if (!jsonString2.Contains("x5c"))
                context.Diffs.Add("x5c is non-empty and should be present in serialized JsonWebKey");

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
