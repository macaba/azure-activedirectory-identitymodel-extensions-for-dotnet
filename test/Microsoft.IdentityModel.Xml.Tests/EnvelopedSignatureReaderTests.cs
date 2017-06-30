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
using System.IO;
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class EnvelopedSignatureReaderTests
    {

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Constructor(EnvelopedSignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.Constructor", theoryData);
            try
            {
                var envelopedReader = new EnvelopedSignatureReader(theoryData.XmlReader);
                while (envelopedReader.Read());

                if (theoryData.ExpectSignature)
                {
                    if (envelopedReader.Signature == null)
                        Assert.False(true, "theoryData.ExpectSignature == true && envelopedReader.ExpectSignature == null");

                    envelopedReader.Signature.Verify(theoryData.SecurityKey);
                }

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<EnvelopedSignatureTheoryData> ConstructorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<EnvelopedSignatureTheoryData>();

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    TestId = "Null XmlReader",
                    XmlReader = null
                });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadSignedXmlTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSignedXml(EnvelopedSignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadSignedXml", theoryData);
            try
            {
                var sr = new StringReader(theoryData.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var envelopedReader = new EnvelopedSignatureReader(reader);
                while(envelopedReader.Read());

                if (theoryData.ExpectSignature)
                {
                    var signature = envelopedReader.Signature;
                    if (signature == null)
                        Assert.False(true, "theoryData.ExpectSignature == true && envelopedReader.Signature == null");

                    signature.Verify(theoryData.SecurityKey);
                }

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<EnvelopedSignatureTheoryData> ReadSignedXmlTheoryData
        {
            get
            {
                var theoryData = new TheoryData<EnvelopedSignatureTheoryData>();

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    TestId = nameof(ReferenceXml.Saml2Token_Valid_Signed) + " No Key",
                    Xml = ReferenceXml.Saml2Token_Valid_Signed
                });

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    SecurityKey = ReferenceXml.DefaultAADSigningKey,
                    TestId = nameof(ReferenceXml.Saml2Token_Valid_Signed),
                    Xml = ReferenceXml.Saml2Token_Valid_Signed
                });

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21019:"),
                    SecurityKey = ReferenceXml.DefaultAADSigningKey,
                    TestId = nameof(ReferenceXml.Saml2Token_TwoSignatures),
                    Xml = ReferenceXml.Saml2Token_TwoSignatures
                });

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.CryptographicException(),
                    SecurityKey = ReferenceXml.DefaultAADSigningKey,
                    TestId = nameof(ReferenceXml.Saml2Token_Valid_SignatureNOTFormated),
                    Xml = ReferenceXml.Saml2Token_Valid_SignatureNOTFormated
                });

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.CryptographicException(),
                    SecurityKey = ReferenceXml.DefaultAADSigningKey,
                    TestId = nameof(ReferenceXml.Saml2Token_Valid_Formated),
                    Xml = ReferenceXml.Saml2Token_Valid_Formated
                });

                return theoryData;
            }
        }
    }
}
